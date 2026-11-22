"""Offscreen tests for role-specific PySide6 workflows."""

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox

import database
import main


class SecureVaultScreenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.qt_app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.database_path_patch = patch.object(
            database,
            "get_database_path",
            lambda base_directory=None: self.root / "backup_system.db",
        )
        self.database_path_patch.start()
        self.iterations_patch = patch.object(
            database, "PASSWORD_HASH_ITERATIONS", 1_000
        )
        self.iterations_patch.start()
        self.logger_patch = patch.object(
            main, "configure_logger", return_value=logging.getLogger("screen-tests")
        )
        self.logger_patch.start()
        self.window = main.SecureVaultApp()

    def tearDown(self) -> None:
        self.window.close()
        self.logger_patch.stop()
        self.iterations_patch.stop()
        self.database_path_patch.stop()
        self.temporary_directory.cleanup()

    def create_accounts_and_login(self) -> None:
        database.register_user("admin_one", "admin-password")
        for slot, username in (("A", "custodian_a"), ("B", "custodian_b")):
            temporary = f"{username}-temporary"
            personal = f"{username}-personal"
            database.create_custodian_user(
                "admin_one", username, temporary, slot=slot
            )
            database.change_user_password(username, temporary, personal)
            database.initialize_custodian_key(
                username, f"{username}-recovery-passphrase"
            )
        self.login_as("admin_one", "admin-password")

    def login_as(self, username: str, password: str) -> None:
        role = database.get_user_role(username)
        if role not in ("operator", "custodian"):
            self.fail(f"Account {username} does not have a supported role.")
        self.window.select_login_mode(role)
        self.window.user_entry.setText(username)
        self.window.password_entry.setText(password)
        self.window.login()

    def create_backup(self) -> int:
        source = self.root / "university"
        source.mkdir()
        (source / "Assignment.pdf").write_bytes(b"assignment contents")
        (source / "Project.docx").write_bytes(b"project contents")
        self.window.backup_name.setText("University Semester Files")
        self.window.backup_source.setText(str(source))
        self.window.backup_archive.setText(str(self.root / "semester.bin"))
        self.window.create_backup_action()
        backups = database.get_backups()
        self.assertEqual(len(backups), 1)
        return backups[0].backup_id

    def test_welcome_and_role_navigation_are_assigned_by_account(self) -> None:
        self.assertIs(self.window.root_stack.currentWidget(), self.window.welcome_page)
        self.assertIn("About", self.window.page_names)
        self.assertEqual(self.window.admin_login_button.text(), "Administrator Sign In")
        self.assertEqual(self.window.custodian_login_button.text(), "Custodian Sign In")
        database.register_user("admin_one", "admin-password")

        self.window.select_login_mode("custodian")
        self.window.user_entry.setText("admin_one")
        self.window.password_entry.setText("admin-password")
        self.window.login()
        self.assertIs(self.window.root_stack.currentWidget(), self.window.login_page)
        self.assertIn("other sign-in option", self.window.login_message.text())

        self.login_as("admin_one", "admin-password")
        self.assertIn("Audit Logs", self.window.allowed_pages)
        self.assertIn("Custodians", self.window.allowed_pages)

        database.create_custodian_user(
            "admin_one", "custodian_a", "temporary-password", slot="A"
        )
        database.change_user_password(
            "custodian_a", "temporary-password", "personal-password"
        )
        self.window.logout()
        self.login_as("custodian_a", "personal-password")
        self.assertEqual(self.window.custodian_slot, "A")
        self.assertEqual(self.window.dashboard_title.text(), "Custodian A Dashboard")
        self.assertIn("Pending Requests", self.window.allowed_pages)
        self.assertIn("My Key Share", self.window.allowed_pages)
        self.assertNotIn("Create Backup", self.window.allowed_pages)
        self.assertTrue(self.window.dashboard_activity_card.isHidden())
        self.assertFalse(hasattr(self.window, "role_combo"))
        self.window.show_page("My Key Share")
        self.window.custodian_passphrase_entry.setText(
            "custodian-a-new-recovery-passphrase"
        )
        self.window.confirm_custodian_passphrase_entry.setText(
            "custodian-a-new-recovery-passphrase"
        )
        self.window.initialize_custodian_key_action()
        self.assertTrue(database.has_custodian_key("custodian_a"))
        with self.assertRaises(PermissionError):
            self.window.show_page("Audit Logs")
        self.assertEqual(
            database.get_recent_activity(1)[0].action, "access_denied"
        )

    def test_backup_history_and_archive_integrity_screen(self) -> None:
        self.create_accounts_and_login()
        backup_id = self.create_backup()
        self.window.show_page("My Backups")
        self.assertEqual(self.window.backup_table.rowCount(), 1)
        self.window.show_page("Verify Backup")
        self.assertEqual(self.window.verify_manifest_table.rowCount(), 2)
        self.window.verify_selected_backup()
        self.assertIn("integrity passed", self.window.verify_backup_status.text())

        archive = self.root / "semester.bin"
        archive.write_bytes(archive.read_bytes() + b"tampered")
        self.window.verify_selected_backup()
        self.assertIn("Integrity check failed", self.window.verify_backup_status.text())
        self.assertIsNotNone(database.get_backup_record(backup_id))

    def test_both_custodians_must_approve_before_restore(self) -> None:
        self.create_accounts_and_login()
        backup_id = self.create_backup()
        self.window.show_page("Restore Backup")
        self.window.request_backup_combo.setCurrentIndex(
            self.window.request_backup_combo.findData(backup_id)
        )
        destination = self.root / "restored"
        self.window.request_destination.setText(str(destination))
        self.window.request_reason.setText("University laptop replacement")
        self.window.create_recovery_request_action()
        self.assertEqual(self.window.operator_request_list.count(), 1)

        for slot, username in (("A", "custodian_a"), ("B", "custodian_b")):
            self.window.logout()
            self.login_as(username, f"{username}-personal")
            self.window.show_page("My Key Share")
            self.assertEqual(self.window.custodian_assignment_table.rowCount(), 1)
            self.assertEqual(
                self.window.custodian_assignment_table.item(0, 2).text(),
                f"Share {slot}",
            )
            self.window.show_page("Pending Requests")
            self.assertEqual(self.window.approval_list.count(), 1)
            if slot == "A":
                self.window.approval_passphrase.setText(
                    "incorrect-custodian-recovery-passphrase"
                )
                self.window.approve_selected_request()
                self.assertIn(
                    "Wrong custodian passphrase",
                    self.window.approval_status.text(),
                )
                failed_event = database.get_recent_activity(1)[0]
                self.assertEqual(failed_event.action, "custodian_approval")
                self.assertEqual(failed_event.outcome, "failure")
                self.assertEqual(
                    main.SecureVaultApp._activity_text(failed_event)[2], "Denied"
                )
            self.window.approval_passphrase.setText(
                f"{username}-recovery-passphrase"
            )
            self.window.approve_selected_request()

        self.window.logout()
        self.login_as("admin_one", "admin-password")
        self.window.show_page("Restore Backup")
        self.window.operator_request_list.setCurrentRow(0)
        self.assertIn(
            "Custodian A (custodian_a): Approved",
            self.window.operator_request_detail.text(),
        )
        self.assertIn(
            "2 of 2 complete", self.window.operator_request_detail.text()
        )
        with patch.object(
            main.QMessageBox,
            "question",
            return_value=QMessageBox.StandardButton.Yes,
        ):
            self.window.restore_approved_request()

        self.assertTrue(
            (destination / "Assignment.pdf").is_file()
        )
        self.assertEqual(self.window.restore_result_table.rowCount(), 2)
        request = database.get_recovery_requests("admin_one")[0]
        self.assertEqual(request.status, "completed")


if __name__ == "__main__":
    unittest.main()
