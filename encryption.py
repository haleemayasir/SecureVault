"""AES-GCM encryption helpers."""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backup_tool import AAD


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt(nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    key = generate_key()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, AAD)
    return key, ciphertext
