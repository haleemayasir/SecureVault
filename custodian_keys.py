"""Custodian RSA key enrollment and encrypted recovery-share envelopes."""

from __future__ import annotations

import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    PublicFormat,
    load_der_public_key,
    load_pem_private_key,
)


MIN_PASSPHRASE_LENGTH = 12
PASSPHRASE_SALT_SIZE = 16
ENVELOPE_MAGIC = b"SVSHARE2"
LEGACY_ENVELOPE_MAGIC = b"SVSHARE1"
LEGACY_ENVELOPE_HEADER_SIZE = len(LEGACY_ENVELOPE_MAGIC) + 32 + 16 + 12
SHARE_SIZE = 33
_KEY_INFO = b"SecureVault recovery share v2"


def _validate_slot(slot: str) -> None:
    if slot not in ("A", "B"):
        raise ValueError("Custodian slot must be A or B.")


def _context(username: str, slot: str, backup_binding: str) -> bytes:
    _validate_slot(slot)
    normalized_username = username.strip().casefold()
    if not normalized_username:
        raise ValueError("Custodian username is required.")
    try:
        if len(backup_binding) != 64:
            raise ValueError
        bytes.fromhex(backup_binding)
    except ValueError as exc:
        raise ValueError("Backup share binding must be a SHA-256 digest.") from exc
    return f"{slot}:{normalized_username}:{backup_binding.casefold()}".encode("utf-8")


def _derive_legacy_private_key(passphrase: str, salt: bytes) -> x25519.X25519PrivateKey:
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(
            f"Custodian passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters."
        )
    if len(salt) != PASSPHRASE_SALT_SIZE:
        raise ValueError("Legacy custodian key salt is malformed.")
    key_material = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    ).derive(passphrase.encode("utf-8"))
    return x25519.X25519PrivateKey.from_private_bytes(key_material)


def create_custodian_identity(passphrase: str) -> tuple[bytes, bytes]:
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(
            f"Custodian passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters."
        )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted_private_key = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    public_key = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return encrypted_private_key, public_key


def validate_legacy_custodian_passphrase(
    passphrase: str,
    salt: bytes,
    expected_public_key: bytes,
) -> bool:
    try:
        private_key = _derive_legacy_private_key(passphrase, salt)
    except ValueError:
        return False
    actual_public_key = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return hmac.compare_digest(actual_public_key, expected_public_key)


def encrypt_share_for_custodian(
    share: bytes | bytearray,
    username: str,
    slot: str,
    backup_binding: str,
    public_key_bytes: bytes,
) -> bytes:
    context = _context(username, slot, backup_binding)
    if len(share) != SHARE_SIZE or share[0] != 0xA5:
        raise ValueError("Recovery share is malformed.")
    try:
        public_key = load_der_public_key(public_key_bytes)
    except ValueError as exc:
        raise ValueError("Custodian public key is malformed.") from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Custodian public key must be RSA.")
    ciphertext = public_key.encrypt(
        bytes(share),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=_KEY_INFO + b"\x00" + context,
        ),
    )
    return ENVELOPE_MAGIC + ciphertext


def _decrypt_legacy_share(
    envelope: bytes,
    username: str,
    slot: str,
    backup_binding: str,
    passphrase: str,
    legacy_salt: bytes | None,
    legacy_public_key: bytes | None,
) -> bytes:
    if legacy_salt is None or legacy_public_key is None:
        raise ValueError("This legacy recovery key is unavailable.")
    context = _context(username, slot, backup_binding)
    if len(envelope) < LEGACY_ENVELOPE_HEADER_SIZE + SHARE_SIZE + 16:
        raise ValueError("Encrypted recovery share is truncated.")

    offset = len(LEGACY_ENVELOPE_MAGIC)
    ephemeral_bytes = envelope[offset : offset + 32]
    offset += 32
    hkdf_salt = envelope[offset : offset + 16]
    offset += 16
    nonce = envelope[offset : offset + 12]
    offset += 12
    ciphertext = envelope[offset:]

    private_key = _derive_legacy_private_key(passphrase, legacy_salt)
    derived_public = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    if not hmac.compare_digest(derived_public, legacy_public_key):
        raise ValueError("Wrong custodian passphrase.")
    try:
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_bytes)
        shared_secret = private_key.exchange(ephemeral_public)
    except ValueError as exc:
        raise ValueError("Encrypted recovery share is malformed.") from exc

    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"SecureVault recovery share v1" + b"\x00" + context,
    ).derive(shared_secret)
    try:
        share = AESGCM(wrapping_key).decrypt(nonce, ciphertext, context)
    except InvalidTag as exc:
        raise ValueError("Could not authenticate this recovery share.") from exc
    if len(share) != SHARE_SIZE or share[0] != 0xA5:
        raise ValueError("Decrypted recovery share is malformed.")
    return share


def decrypt_custodian_share(
    envelope: bytes,
    username: str,
    slot: str,
    backup_binding: str,
    passphrase: str,
    encrypted_private_key: bytes | None,
    expected_public_key: bytes,
    legacy_salt: bytes | None = None,
    legacy_public_key: bytes | None = None,
) -> bytes:
    if envelope.startswith(LEGACY_ENVELOPE_MAGIC):
        return _decrypt_legacy_share(
            envelope,
            username,
            slot,
            backup_binding,
            passphrase,
            legacy_salt,
            legacy_public_key,
        )
    if not envelope.startswith(ENVELOPE_MAGIC):
        raise ValueError("Encrypted recovery share has an unsupported format.")

    context = _context(username, slot, backup_binding)
    if encrypted_private_key is None:
        raise ValueError("Set up your private custodian key before approving.")
    try:
        private_key = load_pem_private_key(
            encrypted_private_key, password=passphrase.encode("utf-8")
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Wrong custodian passphrase.") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Stored custodian private key is not RSA.")
    actual_public_key = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    if not hmac.compare_digest(actual_public_key, expected_public_key):
        raise ValueError("Custodian private key does not match the stored public key.")
    ciphertext = envelope[len(ENVELOPE_MAGIC) :]
    try:
        share = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=_KEY_INFO + b"\x00" + context,
            ),
        )
    except ValueError as exc:
        raise ValueError("Could not authenticate this recovery share.") from exc
    if len(share) != SHARE_SIZE or share[0] != 0xA5:
        raise ValueError("Decrypted recovery share is malformed.")
    return share
