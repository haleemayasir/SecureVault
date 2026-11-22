"""Integrity verification helpers."""

from pathlib import Path

from backup_tool import sha256_bytes, sha256_file


def file_sha256(path: Path) -> str:
    return sha256_file(path)


def bytes_sha256(value: bytes) -> str:
    return sha256_bytes(value)
