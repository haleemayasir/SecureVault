"""Tests for custodian-key enrollment and protected share envelopes."""

import unittest
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from custodian_keys import (
    LEGACY_ENVELOPE_MAGIC,
    _derive_legacy_private_key,
    create_custodian_identity,
    decrypt_custodian_share,
    encrypt_share_for_custodian,
)


class CustodianKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.username = "custodian_a"
        self.slot = "A"
        self.backup_binding = "f" * 64
        self.passphrase = "a-private-recovery-passphrase"
        self.encrypted_private_key, self.public_key = create_custodian_identity(
            self.passphrase
        )
        self.assertTrue(
            self.encrypted_private_key.startswith(
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
            )
        )
        self.share = b"\xa5" + b"S" * 32
        self.envelope = encrypt_share_for_custodian(
            self.share,
            self.username,
            self.slot,
            self.backup_binding,
            self.public_key,
        )

    def test_only_matching_custodian_passphrase_opens_share(self) -> None:
        self.assertEqual(
            decrypt_custodian_share(
                self.envelope,
                self.username,
                self.slot,
                self.backup_binding,
                self.passphrase,
                self.encrypted_private_key,
                self.public_key,
            ),
            self.share,
        )
        with self.assertRaisesRegex(ValueError, "Wrong custodian passphrase"):
            decrypt_custodian_share(
                self.envelope,
                self.username,
                self.slot,
                self.backup_binding,
                "a-different-recovery-passphrase",
                self.encrypted_private_key,
                self.public_key,
            )

    def test_envelope_authentication_binds_share_to_user_and_slot(self) -> None:
        for username, slot in (("custodian_b", "A"), ("custodian_a", "B")):
            with self.subTest(username=username, slot=slot):
                with self.assertRaises(ValueError):
                    decrypt_custodian_share(
                        self.envelope,
                        username,
                        slot,
                        self.backup_binding,
                        self.passphrase,
                        self.encrypted_private_key,
                        self.public_key,
                    )

    def test_tampered_envelope_is_rejected(self) -> None:
        changed = bytearray(self.envelope)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "authenticate"):
            decrypt_custodian_share(
                bytes(changed),
                self.username,
                self.slot,
                self.backup_binding,
                self.passphrase,
                self.encrypted_private_key,
                self.public_key,
            )

    def test_envelope_is_bound_to_the_backup_archive_digest(self) -> None:
        with self.assertRaises(ValueError):
            decrypt_custodian_share(
                self.envelope,
                self.username,
                self.slot,
                "e" * 64,
                self.passphrase,
                self.encrypted_private_key,
                self.public_key,
            )

    def test_existing_x25519_envelopes_remain_recoverable(self) -> None:
        legacy_salt = secrets.token_bytes(16)
        private_key = _derive_legacy_private_key(self.passphrase, legacy_salt)
        legacy_public_key = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        context = (
            f"{self.slot}:{self.username}:{self.backup_binding}".encode("utf-8")
        )
        ephemeral_key = x25519.X25519PrivateKey.generate()
        shared_secret = ephemeral_key.exchange(private_key.public_key())
        hkdf_salt = secrets.token_bytes(16)
        wrapping_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hkdf_salt,
            info=b"SecureVault recovery share v1\x00" + context,
        ).derive(shared_secret)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(wrapping_key).encrypt(
            nonce, self.share, context
        )
        envelope = (
            LEGACY_ENVELOPE_MAGIC
            + ephemeral_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            + hkdf_salt
            + nonce
            + ciphertext
        )
        self.assertEqual(
            decrypt_custodian_share(
                envelope,
                self.username,
                self.slot,
                self.backup_binding,
                self.passphrase,
                None,
                self.public_key,
                legacy_salt,
                legacy_public_key,
            ),
            self.share,
        )


if __name__ == "__main__":
    unittest.main()
