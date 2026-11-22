"""Focused tests for encrypted backup and verified restore results."""

import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from backup_tool import (
    BackupError,
    create_backup,
    create_backup_material,
    main as cli_main,
    restore_backup,
    sha256_file,
)
from custodian_keys import create_custodian_identity, decrypt_custodian_share


class BackupWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "Assignment.pdf").write_bytes(b"sample assignment")
        (self.source / "Project.docx").write_bytes(b"sample project")
        self.passphrase_a = "custodian-a-recovery-passphrase"
        self.passphrase_b = "custodian-b-recovery-passphrase"
        self.private_key_a, self.public_key_a = create_custodian_identity(
            self.passphrase_a
        )
        self.private_key_b, self.public_key_b = create_custodian_identity(
            self.passphrase_b
        )
        self.identity_a = ("custodian_a", self.public_key_a)
        self.identity_b = ("custodian_b", self.public_key_b)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_backup_manifest_and_restore_report_verified_files(self) -> None:
        archive = self.root / "semester.bin"
        created = create_backup_material(
            self.source, archive, self.identity_a, self.identity_b
        )
        self.assertNotIn("custodian_a_share", created)
        self.assertNotIn("custodian_b_share", created)
        share_a = decrypt_custodian_share(
            created["custodian_a_envelope"],
            "custodian_a",
            "A",
            created["archive_sha256"],
            self.passphrase_a,
            self.private_key_a,
            self.public_key_a,
        )
        share_b = decrypt_custodian_share(
            created["custodian_b_envelope"],
            "custodian_b",
            "B",
            created["archive_sha256"],
            self.passphrase_b,
            self.private_key_b,
            self.public_key_b,
        )
        self.assertFalse((self.root / "custodian-a.key").exists())
        restored = restore_backup(
            archive, self.root / "restored", share_a, share_b
        )

        self.assertEqual(created["file_count"], 2)
        self.assertEqual(len(created["files"]), 2)
        self.assertEqual(created["archive_sha256"], sha256_file(archive))
        self.assertEqual(restored["restored_file_count"], 2)
        self.assertEqual(
            {item["status"] for item in restored["verified_files"]}, {"Passed"}
        )
        self.assertEqual(
            (self.root / "restored" / "Assignment.pdf").read_bytes(),
            b"sample assignment",
        )

    def test_backup_archive_cannot_overwrite_source_or_existing_file(self) -> None:
        with self.assertRaisesRegex(BackupError, "outside the source folder"):
            create_backup_material(
                self.source,
                self.source / "archive.bin",
                self.identity_a,
                self.identity_b,
            )
        existing = self.root / "existing.bin"
        existing.write_bytes(b"keep this file")
        with self.assertRaisesRegex(BackupError, "already exists"):
            create_backup_material(
                self.source, existing, self.identity_a, self.identity_b
            )
        self.assertEqual(existing.read_bytes(), b"keep this file")
        with self.assertRaisesRegex(BackupError, "Plaintext share-file export"):
            create_backup(
                self.source,
                self.root / "archive.bin",
                self.root / "share-a.key",
                self.root / "share-b.key",
            )

    def test_standalone_cli_cannot_bypass_custodian_approval(self) -> None:
        errors = StringIO()
        with redirect_stderr(errors):
            result = cli_main(
                ["backup", str(self.source), str(self.root / "backup.bin")]
            )
        self.assertEqual(result, 1)
        self.assertIn("use SecureVault", errors.getvalue())

        errors = StringIO()
        with redirect_stderr(errors):
            result = cli_main(
                ["restore", str(self.root / "backup.bin"), str(self.root / "restored")]
            )
        self.assertEqual(result, 1)
        self.assertIn("both custodians must approve", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
