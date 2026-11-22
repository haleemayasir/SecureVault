"""Focused tests for backup catalog and two-custodian recovery."""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import database
from custodian_keys import encrypt_share_for_custodian


class UserRoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)
        self.iterations_patch = patch.object(
            database, "PASSWORD_HASH_ITERATIONS", 1_000
        )
        self.iterations_patch.start()

    def tearDown(self) -> None:
        self.iterations_patch.stop()
        self.temporary_directory.cleanup()

    def test_existing_users_migrate_to_operator(self) -> None:
        path = database.get_database_path(self.directory)
        salt = b"legacy-salt"
        password_hash = database._hash_password(
            "legacy-password", salt, database.PASSWORD_HASH_ITERATIONS
        )
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                """
                CREATE TABLE users (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    iterations INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            connection.execute(
                """
                INSERT INTO users(username, salt, password_hash, iterations)
                VALUES ('legacy_operator', ?, ?, 1000)
                """,
                (salt, password_hash),
            )
            connection.commit()

        database.initialise_database(self.directory)

        self.assertEqual(
            database.get_user_role("legacy_operator", self.directory),
            "operator",
        )
        self.assertTrue(
            database.authenticate_user(
                "legacy_operator", "legacy-password", self.directory
            )
        )
        self.assertEqual(database.user_count(self.directory), 1)

    def test_dashboard_activity_uses_recent_events_and_last_successful_backup(self) -> None:
        database.initialise_database(self.directory)
        database.record_event(
            "create_backup",
            "success",
            "archive=backup_a.bin; files=2",
            self.directory,
        )
        database.record_event(
            "create_backup",
            "failure",
            "permission denied",
            self.directory,
        )

        recent = database.get_recent_activity(1, self.directory)
        latest_backup = database.get_latest_backup(self.directory)

        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0].outcome, "failure")
        self.assertIsNotNone(latest_backup)
        self.assertEqual(latest_backup.details, "archive=backup_a.bin; files=2")

    def test_first_account_bootstraps_operator_and_later_custodians_approve(self) -> None:
        database.register_user("operator_one", "operator-password", self.directory)
        self.assertEqual(
            database.get_user_role("operator_one", self.directory), "operator"
        )
        self.assertTrue(
            database.authenticate_user(
                "OPERATOR_ONE", "operator-password", self.directory
            )
        )
        with self.assertRaisesRegex(ValueError, "Initial setup is complete"):
            database.register_user("operator_two", "another-password", self.directory)

        database.create_custodian_user(
            "operator_one",
            "custodian_a",
            "custodian-a-password",
            self.directory,
            slot="A",
        )
        database.create_custodian_user(
            "operator_one",
            "custodian_b",
            "custodian-b-password",
            self.directory,
            slot="B",
        )
        with self.assertRaisesRegex(ValueError, "already has an account"):
            database.create_custodian_user(
                "operator_one",
                "another_a",
                "another-password",
                self.directory,
                slot="A",
            )
        self.assertEqual(database.list_custodians(self.directory), [])
        self.assertTrue(database.password_change_required("custodian_a", self.directory))
        with self.assertRaisesRegex(ValueError, "different from the current"):
            database.change_user_password(
                "custodian_a",
                "custodian-a-password",
                "custodian-a-password",
                self.directory,
            )
        database.change_user_password(
            "custodian_a",
            "custodian-a-password",
            "custodian-a-personal-password",
            self.directory,
        )
        self.assertFalse(database.password_change_required("custodian_a", self.directory))
        self.assertFalse(
            database.authenticate_user(
                "custodian_a", "custodian-a-password", self.directory
            )
        )
        self.assertTrue(
            database.authenticate_user(
                "custodian_a", "custodian-a-personal-password", self.directory
            )
        )
        self.assertEqual(database.list_custodians(self.directory), ["custodian_a"])
        with self.assertRaisesRegex(ValueError, "Custodian B"):
            database.create_recovery_request(
                "operator_one",
                "backup.bin",
                "restored",
                "custodian_a",
                "custodian_b",
                "Inactive custodian test",
                self.directory,
            )
        database.change_user_password(
            "custodian_b",
            "custodian-b-password",
            "custodian-b-personal-password",
            self.directory,
        )
        passphrase_a = "custodian-a-recovery"
        passphrase_b = "custodian-b-recovery"
        database.initialize_custodian_key(
            "custodian_a", passphrase_a, self.directory
        )
        database.initialize_custodian_key(
            "custodian_b", passphrase_b, self.directory
        )
        with closing(
            sqlite3.connect(database.get_database_path(self.directory))
        ) as connection:
            encrypted_private_key = connection.execute(
                "SELECT custodian_private_key FROM users WHERE username = 'custodian_a'"
            ).fetchone()[0]
        self.assertTrue(
            encrypted_private_key.startswith(
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
            )
        )
        identity_a = database.get_custodian_public_identity("A", self.directory)
        identity_b = database.get_custodian_public_identity("B", self.directory)
        self.assertIsNotNone(identity_a)
        self.assertIsNotNone(identity_b)
        share_a = b"\xa5" + b"A" * 32
        share_b = b"\xa5" + b"B" * 32
        envelope_a = encrypt_share_for_custodian(
            share_a, identity_a[0], "A", "a" * 64, identity_a[1]
        )
        envelope_b = encrypt_share_for_custodian(
            share_b, identity_b[0], "B", "a" * 64, identity_b[1]
        )
        backup_id = database.create_backup_record(
            "operator_one",
            "University Semester Files",
            "backup.bin",
            "a" * 64,
            2,
            128,
            envelope_a,
            envelope_b,
            [
                {"path": "Assignment.pdf", "size": 64, "sha256": "b" * 64},
                {"path": "Project.docx", "size": 64, "sha256": "c" * 64},
            ],
            self.directory,
        )
        saved_backup = database.get_backup_record(backup_id, self.directory)
        self.assertIsNotNone(saved_backup)
        self.assertEqual(saved_backup.name, "University Semester Files")
        self.assertEqual(len(saved_backup.file_manifest), 2)
        self.assertEqual(saved_backup.share_a_path, "")
        self.assertIsInstance(saved_backup.share_a_envelope, bytes)

        with closing(sqlite3.connect(database.get_database_path(self.directory))) as connection:
            salt = b"unassigned-salt"
            password_hash = database._hash_password(
                "other-password", salt, database.PASSWORD_HASH_ITERATIONS
            )
            connection.execute(
                """
                INSERT INTO users(
                    username, salt, password_hash, iterations, role,
                    must_change_password, custodian_slot
                ) VALUES (?, ?, ?, ?, 'custodian', 0, NULL)
                """,
                ("custodian_other", salt, password_hash, database.PASSWORD_HASH_ITERATIONS),
            )
            connection.commit()
        with self.assertRaisesRegex(ValueError, "Only an operator"):
            database.create_custodian_user(
                "custodian_a",
                "bad_custodian",
                "bad-password",
                self.directory,
                slot="A",
            )

        request_id = database.create_recovery_request(
            "operator_one",
            "backup.bin",
            "restored",
            "custodian_a",
            "custodian_b",
            "Approved class recovery",
            self.directory,
            backup_id,
        )
        self.assertEqual(
            database.get_recovery_requests("operator_one", self.directory)[0].status,
            "pending",
        )
        with self.assertRaisesRegex(ValueError, "both approvals"):
            database.complete_recovery_request(
                "operator_one", request_id, True, "should not restore", self.directory
            )
        with self.assertRaisesRegex(ValueError, "two different custodians"):
            database.create_recovery_request(
                "operator_one",
                "backup.bin",
                "restored",
                "custodian_a",
                "CUSTODIAN_A",
                "Duplicate custodian test",
                self.directory,
            )

        with self.assertRaisesRegex(ValueError, "not assigned"):
            database.approve_recovery_request(
                request_id,
                "custodian_other",
                "other-custodian-recovery",
                self.directory,
            )
        with self.assertRaisesRegex(ValueError, "Wrong custodian passphrase"):
            database.approve_recovery_request(
                request_id,
                "custodian_a",
                "incorrect-custodian-passphrase",
                self.directory,
            )
        released_a = database.approve_recovery_request(
            request_id, "custodian_a", passphrase_a, self.directory
        )
        self.assertEqual(released_a, share_a)
        request = database.get_recovery_requests(
            "operator_one", self.directory
        )[0]
        self.assertEqual(request.status, "a_approved")
        self.assertIsNone(request.custodian_a_share_path)
        with self.assertRaisesRegex(ValueError, "already approved"):
            database.approve_recovery_request(
                request_id,
                "custodian_a",
                passphrase_a,
                self.directory,
            )

        released_b = database.approve_recovery_request(
            request_id, "custodian_b", passphrase_b, self.directory
        )
        self.assertEqual(released_b, share_b)
        request = database.get_recovery_requests(
            "operator_one", self.directory
        )[0]
        self.assertEqual(request.status, "approved")
        with self.assertRaisesRegex(ValueError, "Only an operator"):
            database.complete_recovery_request(
                "custodian_a", request_id, True, "forbidden", self.directory
            )

        database.complete_recovery_request(
            "operator_one", request_id, True, "1 file restored", self.directory
        )
        self.assertEqual(
            database.get_recovery_requests("operator_one", self.directory)[0].status,
            "completed",
        )

        rejected_id = database.create_recovery_request(
            "operator_one",
            "backup.bin",
            "restored_again",
            "custodian_a",
            "custodian_b",
            "Reject test",
            self.directory,
            backup_id,
        )
        database.reject_recovery_request(
            rejected_id, "custodian_a", "Request was not expected.", self.directory
        )
        self.assertEqual(
            database.get_recovery_requests("operator_one", self.directory)[0].status,
            "rejected",
        )
        volatile_id = database.create_recovery_request(
            "operator_one",
            "backup.bin",
            "restored_again",
            "custodian_a",
            "custodian_b",
            "Volatile approval reset test",
            self.directory,
            backup_id,
        )
        database.approve_recovery_request(
            volatile_id, "custodian_a", passphrase_a, self.directory
        )
        self.assertEqual(database.clear_volatile_recovery_approvals(self.directory), 1)
        volatile_request = next(
            item
            for item in database.get_recovery_requests("operator_one", self.directory)
            if item.request_id == volatile_id
        )
        self.assertEqual(volatile_request.status, "pending")
        self.assertIsNone(volatile_request.custodian_a_approved_at)
        database.reject_recovery_request(
            volatile_id,
            "custodian_a",
            "Finish volatile approval reset test.",
            self.directory,
        )
        database.set_custodian_active(
            "operator_one", "custodian_b", False, self.directory
        )
        self.assertFalse(
            database.authenticate_user(
                "custodian_b", "custodian-b-personal-password", self.directory
            )
        )
        database.set_custodian_active(
            "operator_one", "custodian_b", True, self.directory
        )
        database.reset_custodian_password(
            "operator_one", "custodian_b", "temporary-reset-password", self.directory
        )
        self.assertTrue(database.password_change_required("custodian_b", self.directory))


if __name__ == "__main__":
    unittest.main()
