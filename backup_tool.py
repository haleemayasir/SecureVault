#!/usr/bin/env python3
"""Encrypted backup and two-custodian recovery tool for Project 045."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from typing import Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from custodian_keys import encrypt_share_for_custodian


CHUNK_SIZE = 1024 * 1024
MAGIC = b"G6B45V1"
HEADER_SIZE = 4
AAD = b"PBL045-v1"


class BackupError(Exception):
    """A safe, user-facing backup or recovery error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(CHUNK_SIZE):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def collect_files(source: Path) -> list[dict[str, object]]:
    if not source.exists():
        raise BackupError(f"Source does not exist: {source}")
    if not source.is_dir():
        raise BackupError(f"Source must be a directory: {source}")

    entries: list[dict[str, object]] = []
    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(source).as_posix()
        entries.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    return entries


def build_payload(source: Path, manifest: list[dict[str, object]]) -> tuple[bytes, dict[str, object]]:
    chunks: list[bytes] = []
    manifest_by_path = {str(item["path"]): item for item in manifest}
    data: dict[str, str] = {}

    for item in manifest:
        relative = str(item["path"])
        path = source.joinpath(*relative.split("/"))
        data[relative] = path.read_bytes().hex()

    payload_object = {
        "format": "PBL045",
        "manifest": manifest,
        "files": data,
    }
    payload = json.dumps(payload_object, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_digest = sha256_bytes(json.dumps(manifest_by_path, sort_keys=True).encode("utf-8"))
    metadata = {
        "format": "PBL045",
        "payload_sha256": sha256_bytes(payload),
        "manifest_sha256": manifest_digest,
        "file_count": len(manifest),
    }
    return payload, metadata


def atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def split_key(key: bytes) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    share_a = secrets.token_bytes(32)
    share_b = bytes(a ^ b for a, b in zip(share_a, key))
    return b"\xa5" + share_a, b"\xa5" + share_b


def join_key(share_a: bytes, share_b: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(share_a[1:], share_b[1:]))


def create_backup_material(
    source: Path,
    archive: Path,
    custodian_a: tuple[str, bytes],
    custodian_b: tuple[str, bytes],
) -> dict[str, object]:
    source_root = source.resolve()
    archive = archive.resolve()
    if source_root in archive.parents:
        raise BackupError("Save the encrypted archive outside the source folder")
    if archive.exists():
        raise BackupError("The archive file already exists; choose a new location")
    manifest = collect_files(source)
    payload, metadata = build_payload(source, manifest)
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, payload, AAD)

    archive_content = MAGIC + nonce + struct.pack(">I", len(ciphertext)) + ciphertext
    # Write the encrypted archive first. The shares are emitted after archive
    # verification to avoid creating recovery material for an archive that could not be committed.
    atomic_write(archive, archive_content)

    test_nonce = secrets.token_bytes(12)
    verification = AESGCM(data_key).encrypt(test_nonce, b"verification", None)
    AESGCM(data_key).decrypt(test_nonce, verification, None)

    archive_digest = sha256_file(archive)
    share_a, share_b = split_key(data_key)
    envelope_a = encrypt_share_for_custodian(
        share_a,
        custodian_a[0],
        "A",
        archive_digest,
        custodian_a[1],
    )
    envelope_b = encrypt_share_for_custodian(
        share_b,
        custodian_b[0],
        "B",
        archive_digest,
        custodian_b[1],
    )
    return {
        "archive": str(archive),
        "file_count": len(manifest),
        "archive_sha256": archive_digest,
        "custodian_a_envelope": envelope_a,
        "custodian_b_envelope": envelope_b,
        "files": manifest,
    }


def create_backup(
    source: Path,
    archive: Path,
    share_a_path: Path,
    share_b_path: Path,
) -> dict[str, object]:
    del source, archive, share_a_path, share_b_path
    raise BackupError(
        "Plaintext share-file export is disabled. Create backups in the SecureVault app."
    )


def read_archive(archive: Path) -> tuple[bytes, bytes, dict[str, object]]:
    content = archive.read_bytes()
    if not content.startswith(MAGIC):
        raise BackupError("Not a valid PBL045 backup archive")
    offset = len(MAGIC)
    if len(content) < offset + 12 + 4:
        raise BackupError("Backup archive is truncated")
    nonce = content[offset:offset + 12]
    offset += 12
    ciphertext_length = struct.unpack(">I", content[offset:offset + 4])[0]
    offset += 4
    ciphertext = content[offset:]
    if len(ciphertext) != ciphertext_length:
        raise BackupError("Backup archive length mismatch or corruption")
    return nonce, ciphertext, {}


def decrypt_archive(archive: Path, share_a: bytes, share_b: bytes) -> dict[str, object]:
    nonce, ciphertext, _ = read_archive(archive)
    if not isinstance(share_a, bytes) or not isinstance(share_b, bytes):
        raise BackupError(
            "Recovery requires in-memory shares released by both custodians; share-file restore is disabled."
        )
    if any(len(share) != 33 or share[0] != 0xA5 for share in (share_a, share_b)):
        raise BackupError("Invalid in-memory custodian recovery material.")
    data_key = join_key(share_a, share_b)
    try:
        plaintext = AESGCM(data_key).decrypt(nonce, ciphertext, AAD)
    except InvalidTag as exc:
        raise BackupError("Authentication failed: wrong recovery material or corrupted archive") from exc
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("Decrypted payload is malformed") from exc
    return payload


def validate_payload(payload: dict[str, object]) -> list[dict[str, object]]:
    if payload.get("format") != "PBL045":
        raise BackupError("Unsupported or malformed payload")
    manifest = payload.get("manifest")
    files = payload.get("files")
    if not isinstance(manifest, list) or not isinstance(files, dict):
        raise BackupError("Malformed payload manifest")
    return manifest


def restore_backup(
    archive: Path,
    destination: Path,
    share_a: bytes,
    share_b: bytes,
) -> dict[str, object]:
    if destination.exists() and any(destination.iterdir()):
        raise BackupError("Restore destination must be empty")
    destination.mkdir(parents=True, exist_ok=True)

    payload = decrypt_archive(archive, share_a, share_b)
    manifest = validate_payload(payload)
    files = payload["files"]
    restored = 0
    verified_files: list[dict[str, object]] = []
    temp_destination = Path(tempfile.mkdtemp(prefix=".pbl045-", dir=str(destination.parent)))

    try:
        for item in manifest:
            relative = str(item["path"])
            if relative.startswith("/") or ".." in Path(relative).parts:
                raise BackupError(f"Unsafe path in archive: {relative}")
            content_hex = files.get(relative)
            if not isinstance(content_hex, str):
                raise BackupError(f"Missing file in archive: {relative}")
            content = bytes.fromhex(content_hex)
            expected_size = int(item["size"])
            expected_hash = str(item["sha256"])
            if len(content) != expected_size:
                raise BackupError(f"Size mismatch for: {relative}")
            if sha256_bytes(content) != expected_hash:
                raise BackupError(f"SHA-256 mismatch for: {relative}")
            verified_files.append(
                {
                    "path": relative,
                    "size": len(content),
                    "sha256": expected_hash,
                    "status": "Passed",
                }
            )
            target = temp_destination.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(target, content)
            restored += 1

        # Move verified contents into the destination only after every file passes.
        for path in sorted(temp_destination.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_file():
                relative = path.relative_to(temp_destination)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(path, target)
    except Exception:
        shutil.rmtree(temp_destination, ignore_errors=True)
        raise
    else:
        shutil.rmtree(temp_destination, ignore_errors=True)

    return {
        "destination": str(destination),
        "restored_file_count": restored,
        "verified_files": verified_files,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypted backup with 2-of-2 custodian recovery"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup = subparsers.add_parser("backup", help="Create an encrypted backup")
    backup.add_argument("source", type=Path)
    backup.add_argument("archive", type=Path)

    restore = subparsers.add_parser("restore", help="Restore after both custodians release shares")
    restore.add_argument("archive", type=Path)
    restore.add_argument("destination", type=Path)

    subparsers.add_parser("test-key", help="Check that AES key splitting reconstructs correctly")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "backup":
            raise BackupError(
                "Standalone CLI backup is disabled; use SecureVault so custodian shares are protected."
            )
        elif args.command == "restore":
            raise BackupError(
                "Standalone CLI restore is disabled; both custodians must approve inside SecureVault."
            )
        elif args.command == "test-key":
            key = AESGCM.generate_key(bit_length=256)
            a, b = split_key(key)
            print("PASS" if join_key(a, b) == key else "FAIL")
        return 0
    except (BackupError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
