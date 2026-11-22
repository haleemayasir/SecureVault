"""PySide6 desktop interface for SecureVault."""

from __future__ import annotations

import re
import secrets
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QButtonGroup,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QHeaderView,
    QInputDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from backup import create_backup
from backup_tool import BackupError, sha256_file
from database import (
    ActivityEvent,
    RecoveryRequest,
    approve_recovery_request,
    authenticate_user,
    change_user_password,
    complete_recovery_request,
    create_custodian_user,
    create_backup_record,
    create_recovery_request,
    get_backup_record,
    get_backups,
    get_custodian_accounts,
    get_custodian_key_assignments,
    get_custodian_public_identity,
    get_recent_activity,
    get_recovery_requests,
    get_user_profile,
    get_user_role,
    initialise_database,
    initialize_custodian_key,
    has_custodian_key,
    clear_volatile_recovery_approvals,
    password_change_required,
    record_event,
    reject_recovery_request,
    register_user,
    reset_custodian_password,
    set_custodian_active,
    user_count,
)
from logger import configure_logger
from recovery import restore_backup


NAVY = "#111B30"
BLUE = "#3568A8"
BLUE_HOVER = "#2D588F"
TEXT = "#273444"
MUTED = "#718096"
BACKGROUND = "#F4F6F8"
BORDER = "#DCE2E8"
GREEN = "#26734D"
RED = "#A83E3E"


class SecureVaultApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SecureVault - Encrypted Backup")
        self.setMinimumSize(980, 660)
        self.resize(1180, 780)

        self.logger = configure_logger()
        self.username = ""
        self.role = ""
        self.custodian_slot = ""
        self.auth_mode = "operator"
        self.released_shares: dict[int, dict[str, bytearray]] = {}
        initialise_database()
        clear_volatile_recovery_approvals()
        self.first_run = user_count() == 0
        self.setStyleSheet(self.stylesheet())

        self.root_stack = QStackedWidget()
        self.setCentralWidget(self.root_stack)
        self.welcome_page = self.build_welcome_page()
        self.login_page = self.build_login_page()
        self.shell = self.build_app_shell()
        self.root_stack.addWidget(self.welcome_page)
        self.root_stack.addWidget(self.login_page)
        self.root_stack.addWidget(self.shell)
        self.root_stack.setCurrentWidget(self.welcome_page)

    @staticmethod
    def stylesheet() -> str:
        return f"""
            QWidget {{
                color: {TEXT};
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: 10pt;
            }}
            QMainWindow, QWidget#page, QWidget#authPage {{
                background: {BACKGROUND};
            }}
            QLabel#pageTitle {{
                color: {NAVY};
                font-size: 22pt;
                font-weight: 600;
            }}
            QLabel#pageSubtitle, QLabel#muted {{
                color: {MUTED};
            }}
            QFrame#card, QFrame#authCard {{
                background: white;
                border: 1px solid {BORDER};
                border-radius: 8px;
            }}
            QFrame#sidebar {{
                background: {NAVY};
                border: none;
            }}
            QLabel#brandBadge, QLabel#accountAvatar {{
                background: {BLUE};
                color: white;
                border-radius: 7px;
                font-weight: 700;
            }}
            QLabel#brand {{
                color: white;
                font-size: 15pt;
                font-weight: 600;
            }}
            QLabel#brandSubtitle, QLabel#accountRole {{
                color: #9AA8BA;
                font-size: 9pt;
            }}
            QLabel#sidebarMuted {{
                color: #B8C3D0;
            }}
            QLabel#menuLabel {{
                color: #77869B;
                font-size: 8pt;
                font-weight: 600;
            }}
            QFrame#profileCard {{
                background: #192741;
                border: 1px solid #263650;
                border-radius: 8px;
            }}
            QLabel#accountName {{
                color: white;
                font-weight: 600;
            }}
            QLineEdit {{
                min-height: 38px;
                padding: 0 10px;
                background: white;
                border: 1px solid {BORDER};
                border-radius: 5px;
                selection-background-color: {BLUE};
            }}
            QLineEdit:focus {{
                border: 1px solid {BLUE};
            }}
            QPushButton {{
                min-height: 38px;
                padding: 0 14px;
                border: 1px solid {BORDER};
                border-radius: 5px;
                background: white;
                color: {TEXT};
            }}
            QPushButton:hover {{
                background: #EDF1F5;
            }}
            QPushButton:disabled {{
                color: #929BA5;
                background: #E8EBEF;
            }}
            QPushButton#primaryButton {{
                background: {BLUE};
                border-color: {BLUE};
                color: white;
                font-weight: 600;
            }}
            QPushButton#primaryButton:hover {{
                background: {BLUE_HOVER};
                border-color: {BLUE_HOVER};
            }}
            QPushButton#navButton {{
                min-height: 42px;
                padding-left: 14px;
                border: none;
                border-radius: 5px;
                background: transparent;
                color: #E7EDF3;
                text-align: left;
            }}
            QPushButton#navButton:hover {{
                background: #34485F;
            }}
            QPushButton#navButton:checked {{
                background: #3B526D;
                border-left: 3px solid #4E8BFF;
                color: white;
                font-weight: 600;
            }}
            QPushButton#sidebarSignOut {{
                min-height: 22px;
                padding: 0 4px;
                border: none;
                background: transparent;
                color: #C4CFDC;
                font-size: 9pt;
            }}
            QPushButton#sidebarSignOut:hover {{
                color: white;
                background: transparent;
            }}
            QTableWidget {{
                border: none;
                background: white;
                gridline-color: transparent;
                selection-background-color: #F0F4F8;
            }}
            QTableWidget::item {{
                padding: 8px 6px;
                border-bottom: 1px solid #EDF0F3;
            }}
            QHeaderView::section {{
                padding: 8px 6px;
                border: none;
                background: #F8FAFC;
                color: #64748B;
                font-size: 8pt;
                font-weight: 700;
            }}
            QScrollArea {{
                border: none;
                background: {BACKGROUND};
            }}
        """

    def build_login_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("authPage")
        layout = QHBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        intro = QFrame()
        intro.setObjectName("sidebar")
        intro.setFixedWidth(360)
        intro_layout = QVBoxLayout(intro)
        intro_layout.setContentsMargins(42, 42, 38, 42)
        intro_layout.setSpacing(14)

        brand = QLabel("SecureVault")
        brand.setObjectName("brand")
        intro_layout.addWidget(brand)
        intro_layout.addSpacing(66)

        headline = QLabel("Backups you can\ncount on.")
        headline.setStyleSheet("color: white; font-size: 25pt; font-weight: 600;")
        intro_layout.addWidget(headline)
        explanation = QLabel(
            "Keep important files protected and recover them only when both "
            "custodians provide their shares."
        )
        explanation.setObjectName("sidebarMuted")
        explanation.setWordWrap(True)
        intro_layout.addWidget(explanation)
        intro_layout.addSpacing(26)

        for item in (
            "AES-256-GCM encryption",
            "Integrity checks during restore",
            "Two shares required for recovery",
            "Local activity log",
        ):
            feature = QLabel(f"•  {item}")
            feature.setObjectName("sidebarMuted")
            intro_layout.addWidget(feature)
        intro_layout.addStretch()
        local_note = QLabel("Your account is stored on this computer.")
        local_note.setObjectName("sidebarMuted")
        intro_layout.addWidget(local_note)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(36, 36, 36, 36)
        right_layout.addStretch()

        card = QFrame()
        card.setObjectName("authCard")
        card.setMaximumWidth(440)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(36, 34, 36, 30)
        card_layout.setSpacing(8)

        self.auth_title = QLabel(
            "Create Administrator account"
            if self.first_run
            else "Administrator Sign In"
        )
        self.auth_title.setStyleSheet(
            f"color: {NAVY}; font-size: 21pt; font-weight: 600;"
        )
        card_layout.addWidget(self.auth_title)
        self.auth_subtitle = QLabel(
            "Set up the first account to manage SecureVault."
            if self.first_run
            else "Sign in to manage backups and recovery requests."
        )
        self.auth_subtitle.setObjectName("muted")
        card_layout.addWidget(self.auth_subtitle)
        card_layout.addSpacing(14)

        card_layout.addWidget(self.form_label("Username"))
        self.user_entry = QLineEdit()
        self.user_entry.setPlaceholderText("Your username")
        self.user_entry.setClearButtonEnabled(True)
        card_layout.addWidget(self.user_entry)

        card_layout.addWidget(self.form_label("Password"))
        self.password_entry = QLineEdit()
        self.password_entry.setPlaceholderText("Your password")
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        card_layout.addWidget(self.password_entry)

        self.confirm_label = self.form_label("Confirm password")
        self.confirm_entry = QLineEdit()
        self.confirm_entry.setPlaceholderText("Enter your password again")
        self.confirm_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_label.setVisible(self.first_run)
        self.confirm_entry.setVisible(self.first_run)
        card_layout.addWidget(self.confirm_label)
        card_layout.addWidget(self.confirm_entry)

        self.login_message = QLabel("")
        self.login_message.setWordWrap(True)
        card_layout.addWidget(self.login_message)
        card_layout.addSpacing(4)

        self.auth_submit_button = QPushButton(
            "Create Administrator account" if self.first_run else "Sign in"
        )
        self.auth_submit_button.setObjectName("primaryButton")
        self.auth_submit_button.clicked.connect(self.submit_auth)
        card_layout.addWidget(self.auth_submit_button)
        self.auth_back_button = QPushButton("Back to sign-in options")
        self.auth_back_button.clicked.connect(
            lambda: self.root_stack.setCurrentWidget(self.welcome_page)
        )
        card_layout.addWidget(self.auth_back_button)
        self.password_entry.returnPressed.connect(self.submit_auth)
        self.confirm_entry.returnPressed.connect(self.submit_auth)
        right_layout.addWidget(card, alignment=Qt.AlignmentFlag.AlignHCenter)
        right_layout.addStretch()

        layout.addWidget(intro)
        layout.addWidget(right, 1)
        return page

    def build_welcome_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("authPage")
        layout = QHBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addStretch()
        card, content = self.card()
        card.setObjectName("authCard")
        card.setMaximumWidth(560)
        title = QLabel("SecureVault")
        title.setStyleSheet(f"color: {NAVY}; font-size: 26pt; font-weight: 600;")
        subtitle = QLabel("Encrypted Backup & Two-Custodian Recovery System")
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        content.addWidget(title)
        content.addWidget(subtitle)
        content.addSpacing(12)
        description = QLabel(
            "Protect important files with encrypted backups. Recovery requires "
            "separate approval from Custodian A and Custodian B."
        )
        description.setWordWrap(True)
        content.addWidget(description)
        self.admin_login_button = QPushButton("Administrator Sign In")
        self.admin_login_button.setObjectName("primaryButton")
        self.admin_login_button.clicked.connect(
            lambda: self.select_login_mode("operator")
        )
        self.custodian_login_button = QPushButton("Custodian Sign In")
        self.custodian_login_button.clicked.connect(
            lambda: self.select_login_mode("custodian")
        )
        about_button = QPushButton("About SecureVault")
        about_button.clicked.connect(self.show_welcome_about)
        content.addWidget(self.admin_login_button)
        content.addWidget(self.custodian_login_button)
        content.addWidget(about_button)
        layout.addWidget(card, alignment=Qt.AlignmentFlag.AlignVCenter)
        layout.addStretch()
        return page

    @staticmethod
    def form_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet(f"color: {TEXT}; font-weight: 600;")
        return label

    def show_welcome_about(self) -> None:
        QMessageBox.about(
            self,
            "About SecureVault",
            "SecureVault creates AES-256-GCM encrypted backups. Recovery requires "
            "separate approval from Custodian A and Custodian B.",
        )

    def build_app_shell(self) -> QWidget:
        shell = QWidget()
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(230)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(14, 24, 14, 18)
        sidebar_layout.setSpacing(6)

        brand_row = QHBoxLayout()
        brand_row.setContentsMargins(6, 0, 6, 10)
        brand_row.setSpacing(10)
        badge = QLabel("✓")
        badge.setObjectName("brandBadge")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedSize(34, 34)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        brand_name = QLabel("SecureVault")
        brand_name.setObjectName("brand")
        brand_subtitle = QLabel("Encrypted backups")
        brand_subtitle.setObjectName("brandSubtitle")
        brand_text.addWidget(brand_name)
        brand_text.addWidget(brand_subtitle)
        brand_row.addWidget(badge)
        brand_row.addLayout(brand_text)
        brand_row.addStretch()
        sidebar_layout.addLayout(brand_row)

        menu_label = QLabel("MENU")
        menu_label.setObjectName("menuLabel")
        menu_label.setContentsMargins(9, 12, 0, 8)
        sidebar_layout.addWidget(menu_label)

        nav_scroll = QScrollArea()
        nav_scroll.setObjectName("sidebarNav")
        nav_scroll.setWidgetResizable(True)
        nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        nav_scroll.setFrameShape(QFrame.Shape.NoFrame)
        nav_scroll.setStyleSheet("background: transparent;")
        nav_scroll.viewport().setStyleSheet("background: transparent;")
        nav_content = QWidget()
        nav_content.setStyleSheet("background: transparent;")
        nav_layout = QVBoxLayout(nav_content)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(6)

        self.page_stack = QStackedWidget()
        self.page_names = (
            "Dashboard",
            "Create Backup",
            "My Backups",
            "Restore Backup",
            "Verify Backup",
            "Custodians",
            "Audit Logs",
            "Security Alerts",
            "Pending Requests",
            "My Key Share",
            "Approval History",
            "My Profile",
            "Change Password",
            "About",
        )
        self.pages: dict[str, QWidget] = {}
        self.nav_buttons: dict[str, QPushButton] = {}
        self.allowed_pages: set[str] = set()
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        nav_text = {
            "Dashboard": "▦   Dashboard",
            "Create Backup": "↑   Create Backup",
            "My Backups": "▤   My Backups",
            "Restore Backup": "↓   Restore Backup",
            "Verify Backup": "✓   Verify Backup",
            "Custodians": "♙   Custodians",
            "Audit Logs": "≡   Audit Logs",
            "Security Alerts": "!   Security Alerts",
            "Pending Requests": "⌕   My Requests",
            "My Key Share": "♙   Verify Share",
            "Approval History": "✓   Approval History",
            "My Profile": "●   My Profile",
            "Change Password": "⌑   Change Password",
            "About": "i   About SecureVault",
        }
        for index, name in enumerate(self.page_names):
            page = self.build_page(name)
            self.pages[name] = page
            self.page_stack.addWidget(page)
            button = QPushButton(nav_text[name])
            button.setObjectName("navButton")
            button.setCheckable(True)
            button.clicked.connect(
                lambda checked=False, page_name=name: self.show_page(page_name)
            )
            self.nav_group.addButton(button, index)
            self.nav_buttons[name] = button
            nav_layout.addWidget(button)

        nav_layout.addStretch()
        nav_scroll.setWidget(nav_content)
        sidebar_layout.addWidget(nav_scroll, 1)
        profile = QFrame()
        profile.setObjectName("profileCard")
        profile_layout = QHBoxLayout(profile)
        profile_layout.setContentsMargins(9, 9, 9, 8)
        profile_layout.setSpacing(9)
        self.account_avatar = QLabel("")
        self.account_avatar.setObjectName("accountAvatar")
        self.account_avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.account_avatar.setFixedSize(30, 30)
        profile_text = QVBoxLayout()
        profile_text.setSpacing(1)
        self.account_name_label = QLabel("")
        self.account_name_label.setObjectName("accountName")
        self.operator_label = QLabel("")
        self.operator_label.setObjectName("accountRole")
        profile_bottom = QHBoxLayout()
        profile_bottom.setSpacing(4)
        profile_bottom.addWidget(self.operator_label)
        sign_out = QPushButton("Sign out")
        sign_out.setObjectName("sidebarSignOut")
        profile_bottom.addWidget(sign_out)
        profile_text.addWidget(self.account_name_label)
        profile_text.addLayout(profile_bottom)
        profile_layout.addWidget(self.account_avatar)
        profile_layout.addLayout(profile_text, 1)
        sidebar_layout.addWidget(profile)
        sign_out.clicked.connect(self.logout)

        workspace = QWidget()
        workspace_layout = QVBoxLayout(workspace)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        workspace_layout.setSpacing(0)
        workspace_layout.addWidget(self.page_stack, 1)
        footer = QFrame()
        footer.setStyleSheet("background: #E8EDF2;")
        footer.setFixedHeight(34)
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(18, 0, 18, 0)
        self.footer_label = QLabel(
            "SYNTHETIC DATA ONLY - ISOLATED LAB  |  logs/activity.log  |  "
            "backup_system.db  |  PBKDF2 + AES-256-GCM"
        )
        self.footer_label.setStyleSheet("color: #536273; font-size: 8pt;")
        version = QLabel("v1.0")
        version.setStyleSheet("color: #718096; font-size: 9pt;")
        footer_layout.addWidget(self.footer_label)
        footer_layout.addStretch()
        footer_layout.addWidget(version)
        workspace_layout.addWidget(footer)

        shell_layout.addWidget(sidebar)
        shell_layout.addWidget(workspace, 1)
        return shell

    def build_page(self, name: str) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(34, 28, 34, 28)
        outer.setSpacing(12)

        title = QLabel(name)
        title.setObjectName("pageTitle")
        if name == "Dashboard":
            self.dashboard_title = title
        outer.addWidget(title)
        subtitle_text = {
            "Dashboard": "Overview of your vault and recent backup activity.",
            "Create Backup": "Encrypt files and protect each custodian's recovery share.",
            "My Backups": "Browse saved backups and inspect their details.",
            "Restore Backup": "Request recovery and restore only after both approvals.",
            "Verify Backup": "Check the encrypted archive against its recorded SHA-256 digest.",
            "Custodians": "Manage the accounts assigned to each recovery share.",
            "Audit Logs": "Review recorded actions without exposing passwords or key shares.",
            "Security Alerts": "Review failed sign-ins and recovery or backup failures.",
            "Pending Requests": "Review requests assigned to your custodian account.",
            "My Key Share": "Set up the private passphrase that protects your recovery share.",
            "Approval History": "Review recovery decisions recorded for your account.",
            "My Profile": "View your SecureVault account details.",
            "Change Password": "Update the password for your account.",
            "About": "How encrypted backups and two-custodian recovery work.",
        }[name]
        subtitle = QLabel(subtitle_text)
        subtitle.setObjectName("pageSubtitle")
        if name == "Dashboard":
            self.dashboard_subtitle = subtitle
        outer.addWidget(subtitle)

        if name == "Dashboard":
            self.build_dashboard(outer)
        elif name == "Create Backup":
            self.build_backup(outer)
        elif name == "My Backups":
            self.build_backup_history(outer)
        elif name == "Verify Backup":
            self.build_backup_verification(outer)
        elif name == "Custodians":
            self.build_custodians(outer)
        elif name == "Restore Backup":
            self.build_restore(outer)
        elif name == "Pending Requests":
            self.build_approvals(outer)
        elif name == "My Key Share":
            self.build_my_key_share(outer)
        elif name == "Approval History":
            self.build_approval_history(outer)
        elif name == "Audit Logs":
            self.build_audit_logs(outer)
        elif name == "Security Alerts":
            self.build_security_alerts(outer)
        elif name == "My Profile":
            self.build_profile(outer)
        elif name == "Change Password":
            self.build_change_password(outer)
        elif name == "About":
            self.build_about(outer)
        else:
            raise ValueError(f"Unknown page: {name}")
        outer.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(page)
        return scroll

    @staticmethod
    def card() -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)
        return frame, layout

    def build_dashboard(self, layout: QVBoxLayout) -> None:
        cards_row = QHBoxLayout()
        cards_row.setSpacing(14)
        self.dashboard_metric_labels: list[QLabel] = []

        def metric_card(title: str) -> tuple[QFrame, QLabel, QLabel]:
            card, content = self.card()
            label = QLabel(title)
            label.setObjectName("muted")
            self.dashboard_metric_labels.append(label)
            value = QLabel("-")
            value.setStyleSheet(
                f"color: #172235; font-size: 19pt; font-weight: 600;"
            )
            detail = QLabel("")
            detail.setObjectName("muted")
            content.addWidget(label)
            content.addWidget(value)
            content.addWidget(detail)
            return card, value, detail

        total_card, self.total_backups_value, self.total_backups_detail = metric_card(
            "Total backups"
        )
        storage_card, self.storage_value, self.storage_detail = metric_card(
            "Encrypted storage"
        )
        successful_card, self.successful_backups_value, self.successful_backups_detail = metric_card(
            "Successful backups"
        )
        recovery_card, self.recovery_value, self.recovery_detail = metric_card(
            "Pending recovery requests"
        )
        for card in (total_card, storage_card, successful_card, recovery_card):
            cards_row.addWidget(card, 1)
        layout.addLayout(cards_row)

        activity_card, activity_layout = self.card()
        self.dashboard_activity_card = activity_card
        heading = QLabel("Recent activity")
        heading.setStyleSheet(f"color: {NAVY}; font-size: 12pt; font-weight: 600;")
        activity_layout.addWidget(heading)
        self.activity_table = QTableWidget(0, 4)
        self.activity_table.setObjectName("activityTable")
        self.activity_table.setHorizontalHeaderLabels(
            ("TIME", "EVENT", "DETAILS", "STATUS")
        )
        self.activity_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.activity_table.setSelectionMode(
            QAbstractItemView.SelectionMode.NoSelection
        )
        self.activity_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.activity_table.setShowGrid(False)
        self.activity_table.verticalHeader().setVisible(False)
        self.activity_table.verticalHeader().setDefaultSectionSize(46)
        self.activity_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.activity_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.activity_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.activity_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.activity_table.setMinimumHeight(300)
        activity_layout.addWidget(self.activity_table)
        layout.addWidget(activity_card, 1)

    def refresh_dashboard(self) -> None:
        try:
            requests = get_recovery_requests(self.username)
            if self.role == "operator":
                activity = get_recent_activity()
                backups = get_backups()
                storage_size = sum(
                    Path(backup.archive_path).stat().st_size
                    for backup in backups
                    if Path(backup.archive_path).is_file()
                )
                key_ready = False
            else:
                activity = []
                backups = []
                storage_size = 0
                key_ready = has_custodian_key(self.username)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load dashboard data: %s", exc)
            for value in (
                self.total_backups_value,
                self.storage_value,
                self.successful_backups_value,
            ):
                value.setText("Unavailable")
            self.recovery_value.setText("Unavailable")
            self.recovery_detail.clear()
            self._populate_activity_table([])
            return

        if self.role == "custodian":
            self.dashboard_activity_card.hide()
            self.dashboard_subtitle.setText(
                f"Custodian {self.custodian_slot}: review only the recovery requests assigned to you."
                if key_ready
                else "Set up your private recovery key from Verify Share before approving recovery requests."
            )
            for label, title in zip(
                self.dashboard_metric_labels,
                (
                    "Assigned requests",
                    "Awaiting my decision",
                    "My approvals",
                    "Waiting on other custodian",
                ),
            ):
                label.setText(title)
            assigned_open = [
                request
                for request in requests
                if request.status in ("pending", "a_approved", "b_approved")
            ]
            pending = [
                request
                for request in assigned_open
                if self._current_custodian_approval_timestamp(request) is None
            ]
            approved = sum(
                self._current_custodian_approval_timestamp(request) is not None
                for request in requests
            )
            waiting_on_other = sum(
                self._current_custodian_approval_timestamp(request) is not None
                and request.status in ("a_approved", "b_approved")
                for request in assigned_open
            )
            self.total_backups_value.setText(str(len(requests)))
            self.total_backups_detail.setText(
                f"assigned to Custodian {self.custodian_slot}"
            )
            self.storage_value.setText(str(len(pending)))
            self.storage_detail.setText("requests requiring your review")
            self.successful_backups_value.setText(str(approved))
            self.successful_backups_detail.setText("approvals recorded")
            self.recovery_value.setText(str(waiting_on_other))
            self.recovery_detail.setText("waiting for the other custodian")
            self._populate_activity_table([])
            return

        self.dashboard_activity_card.show()
        self.dashboard_subtitle.setText(
            "Manage encrypted backups and review two-custodian recovery progress."
        )
        for label, title in zip(
            self.dashboard_metric_labels,
            (
                "Total backups",
                "Encrypted storage",
                "Successful backups",
                "Pending recovery requests",
            ),
        ):
            label.setText(title)
        self.total_backups_value.setText(str(len(backups)))
        self.total_backups_detail.setText("saved in the backup catalog")
        self.storage_value.setText(self.format_size(storage_size))
        self.storage_detail.setText("encrypted archive files")
        self.successful_backups_value.setText(str(len(backups)))
        self.successful_backups_detail.setText("created and cataloged successfully")

        open_requests = sum(
            request.status in ("pending", "a_approved", "b_approved")
            for request in requests
        )
        self.recovery_value.setText(
            str(open_requests)
        )
        self.recovery_detail.setText(
            f"{sum(request.status == 'approved' for request in requests)} ready to restore · "
            f"{sum(request.status == 'completed' for request in requests)} completed"
        )
        self._populate_activity_table(activity)

    def _current_custodian_approval_timestamp(
        self,
        request: RecoveryRequest,
    ) -> str | None:
        if request.custodian_a.casefold() == self.username.casefold():
            return request.custodian_a_approved_at
        if request.custodian_b.casefold() == self.username.casefold():
            return request.custodian_b_approved_at
        return None

    @staticmethod
    def _display_timestamp(value: str) -> str:
        try:
            timestamp = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return value
        local_time = timestamp.replace(tzinfo=timezone.utc).astimezone()
        if local_time.date() == datetime.now().astimezone().date():
            return f"Today, {local_time:%H:%M}"
        if (datetime.now().astimezone().date() - local_time.date()).days == 1:
            return f"Yesterday, {local_time:%H:%M}"
        return local_time.strftime("%b %d, %H:%M")

    @staticmethod
    def _activity_text(event: ActivityEvent) -> tuple[str, str, str]:
        event_names = {
            "create_backup": "Backup created",
            "recovery_request": "Recovery request",
            "custodian_approval": "Custodian approval",
            "restore_backup": (
                "Restore verified"
                if event.outcome in ("completed", "success")
                else "Restore failed"
                if event.outcome in ("failed", "failure")
                else "Restore"
            ),
            "custodian_account": "Custodian account",
            "password_changed": "Password updated",
            "signup": "Operator account created",
            "login": "Sign in",
            "logout": "Signed out",
            "access_denied": "Access denied",
            "custodian_key_setup": "Custodian key setup",
            "recovery_approval_reset": "Recovery approval reset",
        }
        if event.outcome in ("success", "created", "completed"):
            status = "Success"
        elif event.outcome == "approved":
            status = "Approved"
        elif event.outcome == "pending":
            status = "Pending"
        elif event.outcome in ("a_approved", "b_approved"):
            status = "1 of 2 approved"
        elif event.outcome in ("failure", "failed"):
            status = (
                "Denied"
                if event.action
                in ("login", "recovery_request", "custodian_approval", "access_denied")
                else "Failed"
            )
        else:
            status = event.outcome.replace("_", " ").title()
        return (
            event_names.get(event.action, event.action.replace("_", " ").title()),
            SecureVaultApp._activity_details(event),
            status,
        )

    @staticmethod
    def _activity_details(event: ActivityEvent) -> str:
        if event.action == "create_backup":
            archive = re.search(r"archive=([^;]+)", event.details)
            files = re.search(r"files=(\d+)", event.details)
            if archive and files:
                return f"{archive.group(1)} ({files.group(1)} files)"
            return event.details

        request = re.search(r"request_id=(\d+)", event.details)
        if event.action == "recovery_request" and request:
            operator = re.search(r"operator=([^;]+)", event.details)
            if operator:
                return f"Request #{request.group(1)} · operator {operator.group(1)}"
        if event.action == "custodian_approval" and request:
            custodian = re.search(r"custodian=([^;]+)", event.details)
            if custodian:
                return f"Request #{request.group(1)} · custodian {custodian.group(1)}"
        if event.action == "restore_backup" and request:
            restored_files = re.search(r"(\d+ files restored)", event.details)
            if restored_files:
                return f"Request #{request.group(1)} · {restored_files.group(1)}"
        if event.details.startswith("username="):
            return event.details.removeprefix("username=")
        return event.details

    def _populate_activity_table(self, events: list[ActivityEvent]) -> None:
        self.activity_table.setRowCount(len(events))
        status_colors = {
            "Success": (GREEN, "#E4F4EB"),
            "Approved": (GREEN, "#E4F4EB"),
            "Pending": ("#8A5A10", "#FFF3D6"),
            "1 of 2 approved": (BLUE, "#E8F0FB"),
            "Denied": (RED, "#FCE8E8"),
            "Failed": (RED, "#FCE8E8"),
        }
        for row, event in enumerate(events):
            event_name, details, status = self._activity_text(event)
            values = (
                self._display_timestamp(event.created_at),
                event_name,
                details,
                status,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if column != 3:
                    self.activity_table.setItem(row, column, item)
            foreground, background = status_colors.get(
                status, (MUTED, "#EEF1F4")
            )
            badge = QLabel(status)
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setStyleSheet(
                "QLabel {"
                f" color: {foreground}; background: {background};"
                " border-radius: 11px; padding: 4px 10px;"
                " font-size: 9pt; font-weight: 600; }"
            )
            self.activity_table.setCellWidget(row, 3, badge)

    def build_backup(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        instructions = QLabel(
            "The archive is encrypted before it is saved. Keep Custodian A's "
            "share separate from Custodian B's share."
        )
        instructions.setWordWrap(True)
        content.addWidget(instructions)
        content.addWidget(self.form_label("Backup name"))
        self.backup_name = QLineEdit()
        self.backup_name.setPlaceholderText("For example, University Semester Files")
        content.addWidget(self.backup_name)
        self.backup_source = self.add_path_field(
            content, "Folder to back up", "Choose folder…", "directory"
        )
        self.backup_archive = self.add_path_field(
            content,
            "Encrypted backup file",
            "Save backup…",
            "save_backup",
            str(
                Path("encrypted_backups")
                / f"backup-{datetime.now():%Y%m%d-%H%M%S}.bin"
            ),
        )
        share_note = QLabel(
            "Recovery shares are encrypted directly for each custodian and are "
            "never written as plaintext files."
        )
        share_note.setObjectName("muted")
        share_note.setWordWrap(True)
        content.addWidget(share_note)
        self.backup_status = self.status_label()
        content.addWidget(self.backup_status)
        button = QPushButton("Encrypt and create backup")
        button.setObjectName("primaryButton")
        button.clicked.connect(self.create_backup_action)
        content.addWidget(button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(card)

    def build_backup_history(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        self.backup_table = self.new_table(
            ("BACKUP ID", "BACKUP NAME", "CREATED", "FILES", "SIZE")
        )
        self.backup_table.itemSelectionChanged.connect(self.show_selected_backup)
        content.addWidget(self.backup_table)
        self.backup_detail = QLabel("Select a backup to view its details.")
        self.backup_detail.setWordWrap(True)
        self.backup_detail.setObjectName("muted")
        content.addWidget(self.backup_detail)
        buttons = QHBoxLayout()
        verify = QPushButton("Verify selected backup")
        verify.clicked.connect(self.open_selected_backup_verification)
        request = QPushButton("Request recovery")
        request.setObjectName("primaryButton")
        request.clicked.connect(self.open_selected_backup_request)
        buttons.addWidget(verify)
        buttons.addWidget(request)
        buttons.addStretch()
        content.addLayout(buttons)
        layout.addWidget(card)

    def build_backup_verification(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        content.addWidget(self.form_label("Select backup"))
        self.verify_backup_combo = QComboBox()
        self.verify_backup_combo.currentIndexChanged.connect(
            self.show_verification_manifest
        )
        content.addWidget(self.verify_backup_combo)
        self.verify_backup_status = self.status_label()
        content.addWidget(self.verify_backup_status)
        self.verify_manifest_table = self.new_table(
            ("FILE", "SIZE", "RECORDED SHA-256")
        )
        content.addWidget(self.verify_manifest_table)
        verify = QPushButton("Check encrypted archive")
        verify.setObjectName("primaryButton")
        verify.clicked.connect(self.verify_selected_backup)
        content.addWidget(verify, alignment=Qt.AlignmentFlag.AlignLeft)
        note = QLabel(
            "This screen checks the saved archive digest. Individual file hashes "
            "are verified against the encrypted manifest during restore."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        content.addWidget(note)
        layout.addWidget(card)

    def build_custodians(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        description = QLabel(
            "Assign exactly one account to each share. Custodians set their own "
            "login password and private recovery passphrase. SecureVault generates "
            "their RSA keys automatically; private keys are never displayed here."
        )
        description.setWordWrap(True)
        content.addWidget(description)
        self.custodian_table = self.new_table(
            ("ROLE", "USERNAME", "ACCOUNT STATUS", "PASSWORD STATUS")
        )
        self.custodian_table.itemSelectionChanged.connect(
            self.update_custodian_controls
        )
        content.addWidget(self.custodian_table)
        slot_row = QHBoxLayout()
        slot_row.addWidget(self.form_label("Assign account to"))
        self.custodian_slot_combo = QComboBox()
        self.custodian_slot_combo.addItem("Custodian A", "A")
        self.custodian_slot_combo.addItem("Custodian B", "B")
        slot_row.addWidget(self.custodian_slot_combo)
        slot_row.addStretch()
        content.addLayout(slot_row)
        content.addWidget(self.form_label("Custodian username"))
        self.custodian_username_entry = QLineEdit()
        self.custodian_username_entry.setPlaceholderText("For example, custodian_a")
        content.addWidget(self.custodian_username_entry)
        content.addWidget(self.form_label("Temporary password"))
        self.custodian_password_entry = QLineEdit()
        self.custodian_password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        content.addWidget(self.custodian_password_entry)
        content.addWidget(self.form_label("Confirm password"))
        self.custodian_confirm_entry = QLineEdit()
        self.custodian_confirm_entry.setEchoMode(QLineEdit.EchoMode.Password)
        content.addWidget(self.custodian_confirm_entry)
        self.custodian_status = self.status_label()
        content.addWidget(self.custodian_status)
        self.create_custodian_button = QPushButton("Create custodian account")
        self.create_custodian_button.setObjectName("primaryButton")
        self.create_custodian_button.clicked.connect(self.create_custodian_action)
        content.addWidget(self.create_custodian_button, alignment=Qt.AlignmentFlag.AlignLeft)
        actions = QHBoxLayout()
        self.custodian_toggle_button = QPushButton("Deactivate selected")
        self.custodian_toggle_button.clicked.connect(self.toggle_custodian_action)
        self.custodian_reset_button = QPushButton("Reset temporary password")
        self.custodian_reset_button.clicked.connect(self.reset_custodian_action)
        actions.addWidget(self.custodian_toggle_button)
        actions.addWidget(self.custodian_reset_button)
        actions.addStretch()
        content.addLayout(actions)
        layout.addWidget(card)

    def build_restore(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        content.addWidget(self.form_label("Backup to recover"))
        self.request_backup_combo = QComboBox()
        content.addWidget(self.request_backup_combo)
        self.request_destination = self.add_path_field(
            content,
            "Restore to folder",
            "Choose folder…",
            "directory",
            str(Path("restored_files")),
        )
        content.addWidget(self.form_label("Reason for recovery"))
        self.request_reason = QLineEdit()
        self.request_reason.setPlaceholderText("Briefly explain why recovery is needed")
        content.addWidget(self.request_reason)
        self.restore_request_status = self.status_label()
        content.addWidget(self.restore_request_status)
        request_button = QPushButton("Request custodian approval")
        request_button.setObjectName("primaryButton")
        request_button.clicked.connect(self.create_recovery_request_action)
        content.addWidget(request_button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(card)

        requests_card, requests_content = self.card()
        requests_heading = QLabel("Recovery requests")
        requests_heading.setStyleSheet(
            f"color: {NAVY}; font-size: 12pt; font-weight: 600;"
        )
        requests_content.addWidget(requests_heading)
        self.operator_request_list = QListWidget()
        self.operator_request_list.setMinimumHeight(140)
        self.operator_request_list.setWordWrap(True)
        self.operator_request_list.currentItemChanged.connect(
            self.show_selected_operator_request_details
        )
        requests_content.addWidget(self.operator_request_list)
        self.operator_request_detail = QLabel(
            "Select a request to review the two-custodian authorization status."
        )
        self.operator_request_detail.setWordWrap(True)
        self.operator_request_detail.setObjectName("muted")
        requests_content.addWidget(self.operator_request_detail)
        self.operator_restore_status = self.status_label()
        requests_content.addWidget(self.operator_restore_status)
        self.restore_result_table = self.new_table(
            ("RESTORED FILE", "SIZE", "SHA-256", "INTEGRITY")
        )
        requests_content.addWidget(self.restore_result_table)
        restore_button = QPushButton("Restore selected approved request")
        restore_button.setObjectName("primaryButton")
        restore_button.clicked.connect(self.restore_approved_request)
        requests_content.addWidget(
            restore_button, alignment=Qt.AlignmentFlag.AlignLeft
        )
        layout.addWidget(requests_card)

    def build_approvals(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        description = QLabel(
            "Review the backup and reason before responding. Enter your separate "
            "custodian passphrase to unlock your protected share and approve."
        )
        description.setWordWrap(True)
        content.addWidget(description)
        self.approval_list = QListWidget()
        self.approval_list.setMinimumHeight(220)
        self.approval_list.setWordWrap(True)
        self.approval_list.currentItemChanged.connect(
            self.show_selected_approval_details
        )
        content.addWidget(self.approval_list)
        self.approval_detail = QLabel("Select a request to review its details.")
        self.approval_detail.setWordWrap(True)
        self.approval_detail.setObjectName("muted")
        content.addWidget(self.approval_detail)
        content.addWidget(self.form_label("Custodian passphrase"))
        self.approval_passphrase = QLineEdit()
        self.approval_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.approval_passphrase.setPlaceholderText("Your private recovery passphrase")
        content.addWidget(self.approval_passphrase)
        self.approval_status = self.status_label()
        content.addWidget(self.approval_status)
        actions = QHBoxLayout()
        approve = QPushButton("Approve request")
        approve.setObjectName("primaryButton")
        approve.clicked.connect(self.approve_selected_request)
        reject = QPushButton("Reject request")
        reject.clicked.connect(self.reject_selected_request)
        actions.addWidget(approve)
        actions.addWidget(reject)
        actions.addStretch()
        content.addLayout(actions)
        layout.addWidget(card)

    def build_approval_history(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        self.approval_history_status = self.status_label()
        content.addWidget(self.approval_history_status)
        self.approval_history_table = self.new_table(
            ("REQUEST", "BACKUP", "REQUESTED BY", "STATUS", "DECIDED")
        )
        content.addWidget(self.approval_history_table)
        layout.addWidget(card)

    def build_my_key_share(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        description = QLabel(
            "Recovery shares are assigned to your custodian account automatically "
            "when a backup is created. SecureVault automatically generates your "
            "RSA key pair when you set your private recovery passphrase. The private "
            "key is encrypted, and the Administrator cannot view your key or share."
        )
        description.setWordWrap(True)
        content.addWidget(description)
        assignments_heading = QLabel("Recovery shares assigned to me")
        assignments_heading.setStyleSheet(
            f"color: {NAVY}; font-size: 12pt; font-weight: 600;"
        )
        content.addWidget(assignments_heading)
        self.custodian_assignment_table = self.new_table(
            ("BACKUP", "BACKUP NAME", "ASSIGNED SHARE", "KEY STATUS")
        )
        content.addWidget(self.custodian_assignment_table)
        self.custodian_assignment_status = self.status_label()
        content.addWidget(self.custodian_assignment_status)
        key_heading = QLabel("Secure your recovery key")
        key_heading.setStyleSheet(
            f"color: {NAVY}; font-size: 12pt; font-weight: 600;"
        )
        content.addWidget(key_heading)
        passphrase_description = QLabel(
            "Choose a recovery passphrase separate from your login password. "
            "SecureVault automatically generates your RSA key pair and encrypts "
            "the private key with this passphrase. You never handle key files."
        )
        passphrase_description.setObjectName("muted")
        passphrase_description.setWordWrap(True)
        content.addWidget(passphrase_description)
        content.addWidget(self.form_label("New custodian passphrase"))
        self.custodian_passphrase_entry = QLineEdit()
        self.custodian_passphrase_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.custodian_passphrase_entry.setPlaceholderText("At least 12 characters")
        content.addWidget(self.custodian_passphrase_entry)
        content.addWidget(self.form_label("Confirm passphrase"))
        self.confirm_custodian_passphrase_entry = QLineEdit()
        self.confirm_custodian_passphrase_entry.setEchoMode(QLineEdit.EchoMode.Password)
        content.addWidget(self.confirm_custodian_passphrase_entry)
        self.personal_share_status = self.status_label()
        content.addWidget(self.personal_share_status)
        setup = QPushButton("Set recovery passphrase")
        setup.setObjectName("primaryButton")
        setup.clicked.connect(self.initialize_custodian_key_action)
        content.addWidget(setup, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(card)

    def build_audit_logs(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        self.audit_status = self.status_label()
        content.addWidget(self.audit_status)
        self.audit_table = self.new_table(
            ("TIME", "USER / DETAILS", "ACTIVITY", "OUTCOME")
        )
        content.addWidget(self.audit_table)
        layout.addWidget(card)

    def build_security_alerts(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        self.security_alert_status = self.status_label()
        content.addWidget(self.security_alert_status)
        self.security_alert_table = self.new_table(
            ("TIME", "ACTIVITY", "DETAILS", "OUTCOME")
        )
        content.addWidget(self.security_alert_table)
        layout.addWidget(card)

    def build_profile(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        self.profile_details = QLabel("")
        self.profile_details.setWordWrap(True)
        content.addWidget(self.profile_details)
        change = QPushButton("Change password")
        change.clicked.connect(lambda: self.show_page("Change Password"))
        content.addWidget(change, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(card)

    def build_change_password(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        for label, attribute, placeholder in (
            ("Current password", "current_password_entry", "Current password"),
            ("New password", "new_password_entry", "At least 8 characters"),
            ("Confirm new password", "confirm_new_password_entry", "Enter it again"),
        ):
            content.addWidget(self.form_label(label))
            entry = QLineEdit()
            entry.setPlaceholderText(placeholder)
            entry.setEchoMode(QLineEdit.EchoMode.Password)
            setattr(self, attribute, entry)
            content.addWidget(entry)
        self.password_change_status = self.status_label()
        content.addWidget(self.password_change_status)
        save = QPushButton("Update password")
        save.setObjectName("primaryButton")
        save.clicked.connect(self.change_password_action)
        content.addWidget(save, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(card)

    def build_about(self, layout: QVBoxLayout) -> None:
        card, content = self.card()
        heading = QLabel("Encrypted Backup & Two-Custodian Recovery System")
        heading.setStyleSheet(f"color: {NAVY}; font-size: 13pt; font-weight: 600;")
        content.addWidget(heading)
        explanation = QLabel(
            "SecureVault creates an AES-256-GCM encrypted archive and splits its "
            "random key into two recovery shares. Custodian A and Custodian B "
            "must separately approve a recovery. Restored files are checked "
            "against their recorded SHA-256 hashes before they are written."
        )
        explanation.setWordWrap(True)
        content.addWidget(explanation)
        warning = QLabel(
            "Keep each share with its assigned custodian. Audit logs do not "
            "contain passwords, encryption keys, or share contents."
        )
        warning.setObjectName("muted")
        warning.setWordWrap(True)
        content.addWidget(warning)
        layout.addWidget(card)

    @staticmethod
    def new_table(headers: tuple[str, ...]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setShowGrid(False)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(38)
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        table.horizontalHeader().setStretchLastSection(True)
        table.setMinimumHeight(200)
        return table

    def add_path_field(
        self,
        layout: QVBoxLayout,
        label_text: str,
        browse_text: str,
        mode: str,
        default: str = "",
    ) -> QLineEdit:
        label = self.form_label(label_text)
        layout.addWidget(label)
        row = QHBoxLayout()
        entry = QLineEdit(default)
        entry.setPlaceholderText(label_text)
        browse = QPushButton(browse_text)
        browse.clicked.connect(lambda: self.choose_path(entry, mode))
        row.addWidget(entry, 1)
        row.addWidget(browse)
        layout.addLayout(row)
        return entry

    @staticmethod
    def status_label() -> QLabel:
        label = QLabel("")
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        return label

    def choose_path(self, entry: QLineEdit, mode: str) -> None:
        selected = ""
        if mode == "directory":
            selected = QFileDialog.getExistingDirectory(self, "Select folder")
        elif mode == "save_backup":
            selected, _ = QFileDialog.getSaveFileName(
                self,
                "Save encrypted backup",
                entry.text(),
                "Backup files (*.bin);;All files (*)",
            )
            if selected and not Path(selected).suffix:
                selected += ".bin"
        if selected:
            entry.setText(selected)

    def submit_auth(self) -> None:
        if self.first_run and self.auth_mode == "operator":
            self.signup()
        else:
            self.login()

    def select_login_mode(self, role: str) -> None:
        if role not in ("operator", "custodian"):
            raise ValueError(f"Unknown sign-in role: {role}")
        self.auth_mode = role
        is_admin_setup = self.first_run and role == "operator"
        self.auth_title.setText(
            "Create Administrator account"
            if is_admin_setup
            else "Administrator Sign In"
            if role == "operator"
            else "Custodian Sign In"
        )
        self.auth_subtitle.setText(
            "Set up the first account to manage SecureVault."
            if is_admin_setup
            else "Sign in to manage backups and recovery requests."
            if role == "operator"
            else "Sign in to open your separate custodian workspace."
        )
        self.confirm_label.setVisible(is_admin_setup)
        self.confirm_entry.setVisible(is_admin_setup)
        self.auth_submit_button.setText(
            "Create Administrator account" if is_admin_setup else "Sign in"
        )
        self.user_entry.clear()
        self.password_entry.clear()
        self.confirm_entry.clear()
        self.login_message.clear()
        self.root_stack.setCurrentWidget(self.login_page)

    def login(self) -> None:
        name = self.user_entry.text().strip()
        password = self.password_entry.text()
        if not name or not password:
            self.set_auth_message("Enter your username and password.", False)
            return
        try:
            authenticated = authenticate_user(name, password)
            role = get_user_role(name) if authenticated else None
            if authenticated and role != self.auth_mode:
                record_event(
                    "login",
                    "failure",
                    f"username={name}; expected_role={self.auth_mode}",
                )
                self.set_auth_message(
                    "This account uses the other sign-in option. Return and choose the matching role.",
                    False,
                )
                return
            if authenticated and role == "custodian" and password_change_required(name):
                if not self._change_custodian_password(name, password):
                    self.password_entry.clear()
                    self.set_auth_message(
                        "Set a personal password before using the custodian account.",
                        False,
                    )
                    return
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not authenticate account: %s", exc)
            self.set_auth_message("Could not access the local account database.", False)
            return
        if not authenticated or role not in ("operator", "custodian"):
            self.logger.warning("Login rejected for username: %s", name)
            record_event("login", "failure", f"username={name}")
            self.set_auth_message("Incorrect username or password.", False)
            return

        self.username = name
        self.role = role
        profile = get_user_profile(name)
        self.custodian_slot = (
            profile["custodian_slot"]
            if profile is not None
            else ""
        )
        self.account_name_label.setText(name)
        self.account_avatar.setText(name[:1].upper())
        self.operator_label.setText(
            "Administrator"
            if role == "operator"
            else (
                f"Custodian {self.custodian_slot}"
                if self.custodian_slot
                else "Custodian"
            )
        )
        self.dashboard_title.setText(
            "Administrator Dashboard"
            if role == "operator"
            else (
                f"Custodian {self.custodian_slot} Dashboard"
                if self.custodian_slot
                else "Custodian Dashboard"
            )
        )
        self.footer_label.setText(
            "SYNTHETIC DATA ONLY - ISOLATED LAB  |  logs/activity.log  |  "
            f"backup_system.db  |  Signed in as {name}  |  PBKDF2 + AES-256-GCM"
        )
        self.password_entry.clear()
        self._set_role_pages()
        self.root_stack.setCurrentWidget(self.shell)
        self.show_page("Dashboard")
        self.logger.info("%s signed in: %s", role.title(), name)
        record_event("login", "success", f"username={name}")

    def _change_custodian_password(
        self,
        username: str,
        temporary_password: str,
    ) -> bool:
        dialog = QDialog(self)
        dialog.setWindowTitle("Choose your custodian password")
        dialog.setMinimumWidth(380)
        layout = QVBoxLayout(dialog)
        explanation = QLabel(
            "This account was created by the operator. Set a password only you "
            "know before approving any recovery requests."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        layout.addWidget(self.form_label("New password"))
        password_entry = QLineEdit()
        password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        password_entry.setPlaceholderText("At least 8 characters")
        layout.addWidget(password_entry)
        layout.addWidget(self.form_label("Confirm new password"))
        confirmation_entry = QLineEdit()
        confirmation_entry.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(confirmation_entry)
        error_label = QLabel("")
        error_label.setWordWrap(True)
        error_label.setStyleSheet(f"color: {RED};")
        layout.addWidget(error_label)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        def save_password() -> None:
            new_password = password_entry.text()
            if not new_password or new_password != confirmation_entry.text():
                error_label.setText("Enter the same new password in both fields.")
                return
            try:
                change_user_password(username, temporary_password, new_password)
            except (OSError, sqlite3.Error, ValueError) as exc:
                self.logger.warning("Custodian password change failed: %s", exc)
                error_label.setText(str(exc))
                return
            dialog.accept()

        save_button = buttons.button(QDialogButtonBox.StandardButton.Save)
        if save_button is None:
            raise RuntimeError("Could not create the password-save button.")
        save_button.clicked.connect(save_password)
        return dialog.exec() == QDialog.DialogCode.Accepted

    def signup(self) -> None:
        if not self.first_run:
            self.set_auth_message(
                "Only the first account can be created from this screen.", False
            )
            return
        name = self.user_entry.text().strip()
        password = self.password_entry.text()
        confirmation = self.confirm_entry.text()
        if not name or not password or not confirmation:
            self.set_auth_message(
                "Complete the username and both password fields.", False
            )
            return
        if password != confirmation:
            self.set_auth_message("The passwords do not match.", False)
            return
        try:
            register_user(name, password)
        except (OSError, sqlite3.Error, ValueError) as exc:
            record_event("signup", "failure", str(exc))
            self.logger.warning("Account registration rejected for %s: %s", name, exc)
            self.set_auth_message(str(exc), False)
            return

        self.first_run = False
        self.auth_title.setText("Administrator Sign In")
        self.auth_subtitle.setText("Sign in to manage backups and recovery requests.")
        self.confirm_label.setVisible(False)
        self.confirm_entry.setVisible(False)
        self.auth_submit_button.setText("Sign in")
        self.password_entry.clear()
        self.confirm_entry.clear()
        self.logger.info("Account registered: %s", name)
        record_event("signup", "success", f"username={name}")
        self.set_auth_message(
            "Administrator account created. Sign in with your new credentials.", True
        )

    def set_auth_message(self, message: str, success: bool) -> None:
        self.login_message.setText(message)
        self.login_message.setStyleSheet(
            f"color: {GREEN if success else RED}; padding-top: 4px;"
        )

    def logout(self) -> None:
        self.logger.info("%s signed out: %s", self.role.title(), self.username)
        record_event("logout", "success", f"username={self.username}")
        self.username = ""
        self.role = ""
        self.custodian_slot = ""
        self.user_entry.clear()
        self.password_entry.clear()
        self.confirm_entry.clear()
        self.account_name_label.clear()
        self.account_avatar.clear()
        self.operator_label.clear()
        self.root_stack.setCurrentWidget(self.welcome_page)

    def _set_role_pages(self) -> None:
        if self.role == "operator":
            self.allowed_pages = {
                "Dashboard",
                "Create Backup",
                "My Backups",
                "Verify Backup",
                "Custodians",
                "Restore Backup",
                "Audit Logs",
                "Security Alerts",
                "My Profile",
                "Change Password",
                "About",
            }
        elif self.role == "custodian":
            self.allowed_pages = {
                "Dashboard",
                "Pending Requests",
                "My Key Share",
                "Approval History",
                "My Profile",
                "Change Password",
                "About",
            }
        else:
            raise ValueError(f"Unknown account role: {self.role}")
        for name, button in self.nav_buttons.items():
            button.setVisible(name in self.allowed_pages)

    def show_page(self, name: str) -> None:
        if name not in self.allowed_pages:
            record_event(
                "access_denied",
                "failure",
                f"username={self.username}; role={self.role}; page={name}",
            )
            self.logger.warning(
                "Page access denied: user=%s role=%s page=%s",
                self.username,
                self.role,
                name,
            )
            raise PermissionError(f"The {self.role} role cannot open {name}.")
        if name == "My Key Share" and self.role == "custodian":
            self.refresh_custodian_key_status()
            self.refresh_custodian_key_assignments()
        page = self.pages[name]
        self.page_stack.setCurrentWidget(page)
        button = self.nav_buttons[name]
        if button is not None:
            button.setChecked(True)
        if name == "Dashboard":
            self.refresh_dashboard()
        elif name == "Create Backup":
            self.refresh_custodian_slots()
        elif name == "My Backups":
            self.refresh_backups()
        elif name == "Verify Backup":
            self.refresh_verification_backups()
        elif name == "Custodians":
            self.refresh_custodian_accounts()
        elif name == "Restore Backup":
            self.refresh_requests()
            self.refresh_backups()
        elif name == "Pending Requests":
            self.refresh_requests()
        elif name == "Approval History":
            self.refresh_approval_history()
        elif name == "Audit Logs":
            self.refresh_audit_logs()
        elif name == "Security Alerts":
            self.refresh_security_alerts()
        elif name == "My Profile":
            self.refresh_profile()

    @staticmethod
    def format_size(size: int) -> str:
        value = float(size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024 or unit == "TB":
                return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            value /= 1024
        return f"{size} B"

    def refresh_backups(self) -> None:
        try:
            backups = get_backups()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load backup history: %s", exc)
            self.backup_table.setRowCount(0)
            self.backup_detail.setText(f"Could not load backup history: {exc}")
            return
        self.backup_records = {backup.backup_id: backup for backup in backups}
        self.backup_table.setRowCount(len(backups))
        for row, backup in enumerate(backups):
            values = (
                f"BK{backup.backup_id:03d}",
                backup.name,
                self._display_timestamp(backup.created_at),
                str(backup.file_count),
                self.format_size(backup.size_bytes),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, backup.backup_id)
                self.backup_table.setItem(row, column, item)
        current_id = self.request_backup_combo.currentData()
        self.request_backup_combo.clear()
        for backup in backups:
            self.request_backup_combo.addItem(
                f"BK{backup.backup_id:03d} - {backup.name}", backup.backup_id
            )
        if current_id is not None:
            index = self.request_backup_combo.findData(current_id)
            if index >= 0:
                self.request_backup_combo.setCurrentIndex(index)
        self.show_selected_backup()

    def refresh_custodian_slots(self) -> None:
        try:
            accounts = get_custodian_accounts()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load custodian assignments: %s", exc)
            self.set_status(
                self.backup_status, False, f"Could not load custodian accounts: {exc}"
            )
            return
        active = {
            account.slot: account.username
            for account in accounts
            if account.slot and account.is_active and not account.must_change_password
        }
        configured = [
            f"Custodian {slot}: {active.get(slot, 'not configured')}"
            for slot in ("A", "B")
        ]
        ready = all(slot in active for slot in ("A", "B"))
        self.set_status(
            self.backup_status,
            ready,
            "Recovery shares will be assigned to " + " · ".join(configured),
        )

    def refresh_custodian_accounts(self) -> None:
        try:
            accounts = get_custodian_accounts()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load custodian accounts: %s", exc)
            self.custodian_table.setRowCount(0)
            self.set_status(
                self.custodian_status, False, f"Could not load custodian accounts: {exc}"
            )
            return
        self.custodian_table.setRowCount(len(accounts))
        for row, account in enumerate(accounts):
            slot_name = (
                f"Custodian {account.slot}" if account.slot else "Unassigned"
            )
            status = "Active" if account.is_active else "Inactive"
            password_status = (
                "Temporary password"
                if account.must_change_password
                else "Personal password set"
            )
            for column, value in enumerate(
                (slot_name, account.username, status, password_status)
            ):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, account.username)
                self.custodian_table.setItem(row, column, item)
        occupied_slots = {
            account.slot for account in accounts if account.slot is not None
        }
        selected_slot = self.custodian_slot_combo.currentData()
        self.custodian_slot_combo.clear()
        for slot in ("A", "B"):
            if slot not in occupied_slots:
                self.custodian_slot_combo.addItem(f"Custodian {slot}", slot)
        if selected_slot is not None:
            index = self.custodian_slot_combo.findData(selected_slot)
            if index >= 0:
                self.custodian_slot_combo.setCurrentIndex(index)
        self.create_custodian_button.setEnabled(
            self.custodian_slot_combo.count() > 0
        )
        self.update_custodian_controls()

    def update_custodian_controls(self) -> None:
        row = self.custodian_table.currentRow()
        if row < 0:
            self.custodian_toggle_button.setEnabled(False)
            self.custodian_reset_button.setEnabled(False)
            return
        active_item = self.custodian_table.item(row, 2)
        active = active_item is not None and active_item.text() == "Active"
        self.custodian_toggle_button.setText(
            "Deactivate selected" if active else "Activate selected"
        )
        self.custodian_toggle_button.setEnabled(True)
        self.custodian_reset_button.setEnabled(True)

    def selected_custodian_username(self) -> str | None:
        row = self.custodian_table.currentRow()
        if row < 0:
            return None
        item = self.custodian_table.item(row, 1)
        return str(item.data(Qt.ItemDataRole.UserRole)) if item is not None else None

    def toggle_custodian_action(self) -> None:
        username = self.selected_custodian_username()
        if username is None:
            return
        row = self.custodian_table.currentRow()
        active_item = self.custodian_table.item(row, 2)
        is_active = active_item is not None and active_item.text() == "Active"
        try:
            set_custodian_active(self.username, username, not is_active)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.set_status(self.custodian_status, False, str(exc))
            return
        self.set_status(
            self.custodian_status,
            True,
            f"{username} is now {'inactive' if is_active else 'active'}.",
        )
        self.refresh_custodian_accounts()
        self.refresh_custodian_slots()

    def reset_custodian_action(self) -> None:
        username = self.selected_custodian_username()
        if username is None:
            return
        temporary_password = secrets.token_urlsafe(12)
        try:
            reset_custodian_password(self.username, username, temporary_password)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.set_status(self.custodian_status, False, str(exc))
            return
        self.refresh_custodian_accounts()
        QMessageBox.information(
            self,
            "Temporary password created",
            f"Provide this temporary password privately to {username}:\n\n"
            f"{temporary_password}\n\nIt will need to be changed at next sign-in.",
        )

    def show_selected_backup(self) -> None:
        if not hasattr(self, "backup_table"):
            return
        row = self.backup_table.currentRow()
        if row < 0:
            self.backup_detail.setText("Select a backup to view its details.")
            return
        item = self.backup_table.item(row, 0)
        if item is None:
            return
        backup = self.backup_records.get(int(item.data(Qt.ItemDataRole.UserRole)))
        if backup is None:
            return
        file_names = ", ".join(
            f"{entry.get('path', '')} ({self.format_size(int(entry.get('size', 0)))})"
            for entry in backup.file_manifest
        )
        self.backup_detail.setText(
            f"Archive: {backup.archive_path}\n"
            "Encryption: AES-256-GCM\n"
            f"SHA-256: {backup.archive_sha256}\n"
            f"Custodian A: {backup.custodian_a} · Custodian B: {backup.custodian_b}\n"
            f"Files: {file_names or 'No files'}"
        )

    def selected_backup_id(self) -> int | None:
        row = self.backup_table.currentRow()
        if row < 0:
            return None
        item = self.backup_table.item(row, 0)
        return int(item.data(Qt.ItemDataRole.UserRole)) if item is not None else None

    def open_selected_backup_verification(self) -> None:
        backup_id = self.selected_backup_id()
        if backup_id is None:
            return
        self.show_page("Verify Backup")
        index = self.verify_backup_combo.findData(backup_id)
        if index >= 0:
            self.verify_backup_combo.setCurrentIndex(index)

    def open_selected_backup_request(self) -> None:
        backup_id = self.selected_backup_id()
        if backup_id is None:
            return
        self.show_page("Restore Backup")
        index = self.request_backup_combo.findData(backup_id)
        if index >= 0:
            self.request_backup_combo.setCurrentIndex(index)

    def refresh_verification_backups(self) -> None:
        try:
            backups = get_backups()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load backups for verification: %s", exc)
            self.verify_backup_combo.clear()
            self.verify_manifest_table.setRowCount(0)
            self.set_status(
                self.verify_backup_status,
                False,
                f"Could not load backups for verification: {exc}",
            )
            return
        self.verify_backup_combo.clear()
        for backup in backups:
            self.verify_backup_combo.addItem(
                f"BK{backup.backup_id:03d} - {backup.name}", backup.backup_id
            )
        self.show_verification_manifest()

    def show_verification_manifest(self) -> None:
        if not hasattr(self, "verify_manifest_table"):
            return
        backup_id = self.verify_backup_combo.currentData()
        backup = (
            self.backup_records.get(int(backup_id))
            if backup_id is not None and hasattr(self, "backup_records")
            else None
        )
        if backup is None and backup_id is not None:
            backup = get_backup_record(int(backup_id))
        self.verify_manifest_table.setRowCount(0)
        if backup is None:
            self.set_status(
                self.verify_backup_status, False, "No backup is available to verify."
            )
            return
        self.verify_manifest_table.setRowCount(len(backup.file_manifest))
        for row, entry in enumerate(backup.file_manifest):
            for column, value in enumerate(
                (
                    str(entry.get("path", "")),
                    self.format_size(int(entry.get("size", 0))),
                    str(entry.get("sha256", "")),
                )
            ):
                self.verify_manifest_table.setItem(
                    row, column, QTableWidgetItem(value)
                )
        self.set_status(
            self.verify_backup_status,
            True,
            f"BK{backup.backup_id:03d} · {len(backup.file_manifest)} files recorded.",
        )

    def verify_selected_backup(self) -> None:
        backup_id = self.verify_backup_combo.currentData()
        if backup_id is None:
            self.set_status(
                self.verify_backup_status, False, "Select a backup to verify."
            )
            return
        backup = get_backup_record(int(backup_id))
        if backup is None:
            self.set_status(
                self.verify_backup_status, False, "The selected backup no longer exists."
            )
            return
        try:
            actual_digest = sha256_file(Path(backup.archive_path))
        except (OSError, ValueError) as exc:
            self.set_status(self.verify_backup_status, False, str(exc))
            return
        if actual_digest != backup.archive_sha256:
            self.set_status(
                self.verify_backup_status,
                False,
                "Integrity check failed: the archive digest does not match.",
            )
            return
        self.set_status(
            self.verify_backup_status,
            True,
            f"Archive integrity passed. SHA-256: {actual_digest}",
        )

    def refresh_approval_history(self) -> None:
        try:
            requests = get_recovery_requests(self.username)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load approval history: %s", exc)
            self.approval_history_table.setRowCount(0)
            self.set_status(
                self.approval_history_status,
                False,
                f"Could not load approval history: {exc}",
            )
            return
        self.set_status(
            self.approval_history_status,
            True,
            f"Showing {len(requests)} requests assigned to your account.",
        )
        self.approval_history_table.setRowCount(len(requests))
        for row, request in enumerate(requests):
            backup = (
                get_backup_record(request.backup_id)
                if request.backup_id is not None
                else None
            )
            slot_approval = self._current_custodian_approval_timestamp(request)
            values = (
                f"RR{request.request_id:03d}",
                backup.name if backup is not None else Path(request.archive_path).name,
                request.created_by,
                request.status.replace("_", " ").title(),
                self._display_timestamp(slot_approval)
                if slot_approval
                else "—",
            )
            for column, value in enumerate(values):
                self.approval_history_table.setItem(
                    row, column, QTableWidgetItem(value)
                )

    def _request_for_id(self, request_id: int) -> RecoveryRequest | None:
        return next(
            (
                request
                for request in getattr(self, "current_requests", [])
                if request.request_id == request_id
            ),
            None,
        )

    def show_selected_approval_details(
        self,
        current: QListWidgetItem | None,
        previous: QListWidgetItem | None,
    ) -> None:
        if current is previous:
            return
        request_id = (
            int(current.data(Qt.ItemDataRole.UserRole))
            if current is not None
            else None
        )
        request = self._request_for_id(request_id) if request_id is not None else None
        if request is None:
            self.approval_detail.setText("Select a request to review its details.")
            return
        backup = (
            get_backup_record(request.backup_id)
            if request.backup_id is not None
            else None
        )
        backup_name = (
            backup.name if backup is not None else Path(request.archive_path).name
        )
        self.approval_detail.setText(
            f"Backup: {backup_name}\nRequested by: {request.created_by}\n"
            f"Reason: {request.reason}\n"
            f"Custodian A: {request.custodian_a} · "
            f"Custodian B: {request.custodian_b}\n"
            f"Status: {request.status.replace('_', ' ').title()}"
        )

    def show_selected_operator_request_details(
        self,
        current: QListWidgetItem | None,
        previous: QListWidgetItem | None,
    ) -> None:
        if current is previous:
            return
        request_id = (
            int(current.data(Qt.ItemDataRole.UserRole))
            if current is not None
            else None
        )
        request = self._request_for_id(request_id) if request_id is not None else None
        if request is None:
            self.operator_request_detail.setText(
                "Select a request to review the two-custodian authorization status."
            )
            return
        status_a = (
            "Approved"
            if request.custodian_a_approved_at is not None
            else "Pending"
        )
        status_b = (
            "Approved"
            if request.custodian_b_approved_at is not None
            else "Pending"
        )
        approval_count = sum(
            approval is not None
            for approval in (
                request.custodian_a_approved_at,
                request.custodian_b_approved_at,
            )
        )
        if request.status == "rejected":
            authorization = "Request rejected; restore is blocked."
        elif request.status == "completed":
            authorization = "Recovery completed."
        elif request.status == "failed":
            authorization = "Restore failed."
        elif approval_count == 2 and request.status == "approved":
            authorization = "Recovery can proceed."
        else:
            authorization = f"Waiting for {2 - approval_count} custodian approval(s)."
        self.operator_request_detail.setText(
            f"Recovery request RR{request.request_id:03d}\n"
            f"Custodian A ({request.custodian_a}): {status_a}\n"
            f"Custodian B ({request.custodian_b}): {status_b}\n"
            f"Authorization: {approval_count} of 2 complete — {authorization}"
        )

    def refresh_audit_logs(self) -> None:
        try:
            events = get_recent_activity(100)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load audit log: %s", exc)
            self.set_status(self.audit_status, False, f"Could not load audit log: {exc}")
            return
        self.set_status(self.audit_status, True, f"Showing {len(events)} recent events.")
        self.audit_table.setRowCount(len(events))
        for row, event in enumerate(events):
            event_name, details, status = self._activity_text(event)
            values = (
                self._display_timestamp(event.created_at),
                details,
                event_name,
                status,
            )
            for column, value in enumerate(values):
                self.audit_table.setItem(row, column, QTableWidgetItem(value))

    def refresh_security_alerts(self) -> None:
        try:
            events = [
                event
                for event in get_recent_activity(100)
                if event.outcome in ("failure", "failed", "rejected")
            ]
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load security alerts: %s", exc)
            self.set_status(
                self.security_alert_status,
                False,
                f"Could not load security alerts: {exc}",
            )
            return
        self.set_status(
            self.security_alert_status, True, f"Showing {len(events)} recent alerts."
        )
        self.security_alert_table.setRowCount(len(events))
        for row, event in enumerate(events):
            outcome = (
                "Denied"
                if event.action in ("custodian_approval", "access_denied")
                and event.outcome in ("failure", "failed")
                else event.outcome.replace("_", " ").title()
            )
            values = (
                self._display_timestamp(event.created_at),
                event.action.replace("_", " ").title(),
                event.details,
                outcome,
            )
            for column, value in enumerate(values):
                self.security_alert_table.setItem(row, column, QTableWidgetItem(value))

    def refresh_profile(self) -> None:
        try:
            profile = get_user_profile(self.username)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load account profile: %s", exc)
            self.profile_details.setText(f"Could not load account details: {exc}")
            return
        if profile is None:
            self.profile_details.setText("Account details are unavailable.")
            return
        role = (
            "Administrator"
            if profile["role"] == "operator"
            else f"Custodian {profile['custodian_slot'] or 'Unassigned'}"
        )
        self.profile_details.setText(
            f"Username: {profile['username']}\n"
            f"Role: {role}\n"
            f"Account status: {profile['is_active']}\n"
            f"Created: {profile['created_at']}"
        )

    def change_password_action(self) -> None:
        current = self.current_password_entry.text()
        new = self.new_password_entry.text()
        confirmation = self.confirm_new_password_entry.text()
        if not current or not new or not confirmation:
            self.set_status(
                self.password_change_status, False, "Complete all password fields."
            )
            return
        if new != confirmation:
            self.set_status(
                self.password_change_status, False, "The new passwords do not match."
            )
            return
        try:
            change_user_password(self.username, current, new)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.set_status(self.password_change_status, False, str(exc))
            return
        self.current_password_entry.clear()
        self.new_password_entry.clear()
        self.confirm_new_password_entry.clear()
        self.set_status(
            self.password_change_status, True, "Password updated successfully."
        )

    def create_backup_action(self) -> None:
        if self.role != "operator":
            raise PermissionError("Only an operator can create backups.")
        name = self.backup_name.text().strip()
        values = (
            self.backup_source.text().strip(),
            self.backup_archive.text().strip(),
        )
        if not name or not all(values):
            self.set_status(
                self.backup_status, False, "Enter a backup name, source folder, and archive file."
            )
            return
        try:
            active_slots = {
                account.slot
                for account in get_custodian_accounts()
                if account.slot
                and account.is_active
                and not account.must_change_password
            }
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not verify custodian assignments: %s", exc)
            self.set_status(
                self.backup_status, False, f"Could not verify custodians: {exc}"
            )
            return
        if active_slots != {"A", "B"}:
            self.set_status(
                self.backup_status,
                False,
                "Create or activate both custodian accounts and have them set personal passwords first.",
            )
            return
        source, archive = (Path(value) for value in values)
        try:
            custodian_a = get_custodian_public_identity("A")
            custodian_b = get_custodian_public_identity("B")
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.set_status(self.backup_status, False, f"Could not load custodian keys: {exc}")
            return
        if custodian_a is None or custodian_b is None:
            self.set_status(
                self.backup_status,
                False,
                "Both custodians must set their private recovery passphrases before a backup can be created.",
            )
            return
        try:
            result = create_backup(source, archive, custodian_a, custodian_b)
            manifest = result.get("files")
            if not isinstance(manifest, list) or not all(
                isinstance(item, dict) for item in manifest
            ):
                raise ValueError("Backup service returned an invalid file manifest.")
            envelope_a = result.get("custodian_a_envelope")
            envelope_b = result.get("custodian_b_envelope")
            if not isinstance(envelope_a, bytes) or not isinstance(envelope_b, bytes):
                raise ValueError("Backup service did not return protected custodian shares.")
            saved_archive = Path(str(result["archive"]))
            backup_id = create_backup_record(
                self.username,
                name,
                str(saved_archive),
                str(result["archive_sha256"]),
                int(result["file_count"]),
                saved_archive.stat().st_size,
                envelope_a,
                envelope_b,
                manifest,
            )
            self.logger.info(
                "Encrypted backup created: id=%s files=%s",
                backup_id,
                result["file_count"],
            )
            self.set_status(
                self.backup_status,
                True,
                f"Backup BK{backup_id:03d} ({name}) created successfully. "
                "Encrypted recovery shares are assigned to both custodians.",
            )
            self.refresh_backups()
            self.refresh_dashboard()
        except (BackupError, OSError, sqlite3.Error, ValueError) as exc:
            record_event("create_backup", "failure", str(exc))
            self.logger.error("Backup failed: %s", exc)
            self.set_status(self.backup_status, False, str(exc))

    def initialize_custodian_key_action(self) -> None:
        if self.role != "custodian":
            raise PermissionError("Only a custodian can create a recovery key.")
        passphrase = self.custodian_passphrase_entry.text()
        confirmation = self.confirm_custodian_passphrase_entry.text()
        if passphrase != confirmation:
            self.set_status(
                self.personal_share_status, False, "The passphrases do not match."
            )
            return
        try:
            initialize_custodian_key(self.username, passphrase)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.set_status(self.personal_share_status, False, str(exc))
            return
        self.custodian_passphrase_entry.clear()
        self.confirm_custodian_passphrase_entry.clear()
        self.set_status(
            self.personal_share_status,
            True,
            "Your RSA recovery key is ready. Keep your passphrase safe; it cannot be reset by the Administrator.",
        )
        self.refresh_custodian_key_status()
        self.refresh_custodian_key_assignments()

    def refresh_custodian_key_status(self) -> None:
        try:
            ready = has_custodian_key(self.username)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not check custodian key status: %s", exc)
            self.set_status(
                self.personal_share_status, False, f"Could not check key status: {exc}"
            )
            return
        self.custodian_passphrase_entry.setEnabled(not ready)
        self.confirm_custodian_passphrase_entry.setEnabled(not ready)
        setup_buttons = self.pages["My Key Share"].findChildren(QPushButton)
        for button in setup_buttons:
            if button.text() == "Set recovery passphrase":
                button.setEnabled(not ready)
        if ready:
            self.set_status(
                self.personal_share_status,
                True,
                "Your recovery key is set up. You can use your passphrase to approve requests.",
            )

    def refresh_custodian_key_assignments(self) -> None:
        try:
            assignments = get_custodian_key_assignments(self.username)
            key_ready = has_custodian_key(self.username)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error("Could not load custodian key assignments: %s", exc)
            self.set_status(
                self.custodian_assignment_status,
                False,
                f"Could not load assigned recovery shares: {exc}",
            )
            return
        self.custodian_assignment_table.setRowCount(len(assignments))
        for row, assignment in enumerate(assignments):
            values = (
                f"BK{assignment.backup_id:03d}",
                assignment.backup_name,
                f"Share {assignment.slot}",
                "Ready to unlock" if key_ready else "Set up your private key",
            )
            for column, value in enumerate(values):
                self.custodian_assignment_table.setItem(
                    row, column, QTableWidgetItem(value)
                )
        if assignments:
            message = (
                f"{len(assignments)} protected share(s) are assigned to you."
            )
        else:
            message = "No recovery shares assigned yet. They will appear here automatically when backups are created."
        self.set_status(self.custodian_assignment_status, True, message)

    def create_custodian_action(self) -> None:
        if self.role != "operator":
            raise PermissionError("Only an operator can create custodian accounts.")
        username = self.custodian_username_entry.text().strip()
        password = self.custodian_password_entry.text()
        confirmation = self.custodian_confirm_entry.text()
        if not username or not password or not confirmation:
            self.set_status(
                self.custodian_status,
                False,
                "Complete the username and both password fields.",
            )
            return
        if password != confirmation:
            self.set_status(
                self.custodian_status, False, "The passwords do not match."
            )
            return
        try:
            slot = self.custodian_slot_combo.currentData()
            if slot not in ("A", "B"):
                self.set_status(
                    self.custodian_status,
                    False,
                    "Both custodian account slots are already assigned.",
                )
                return
            create_custodian_user(
                self.username, username, password, slot=slot
            )
            record_event(
                "custodian_account", "created", f"slot={slot}; username={username}"
            )
            self.logger.info("Custodian account created: %s", username)
            self.custodian_username_entry.clear()
            self.custodian_password_entry.clear()
            self.custodian_confirm_entry.clear()
            self.set_status(
                self.custodian_status,
                True,
                f"Custodian {slot} account created for {username}. Share the temporary login details privately.",
            )
            self.refresh_custodian_accounts()
            self.refresh_custodian_slots()
        except (OSError, sqlite3.Error, ValueError) as exc:
            record_event(
                "custodian_account",
                "failure",
                f"username={username}; {exc}",
            )
            self.logger.warning("Could not create custodian account: %s", exc)
            self.set_status(self.custodian_status, False, str(exc))

    def create_recovery_request_action(self) -> None:
        if self.role != "operator":
            raise PermissionError("Only an operator can request recovery.")
        backup_id_value = self.request_backup_combo.currentData()
        destination = self.request_destination.text().strip()
        reason = self.request_reason.text().strip()
        if backup_id_value is None or not destination or not reason:
            self.set_status(
                self.restore_request_status,
                False,
                "Select a backup and complete the destination and reason.",
            )
            return
        backup_id = int(backup_id_value)
        backup = get_backup_record(backup_id)
        if backup is None:
            self.set_status(
                self.restore_request_status, False, "The selected backup no longer exists."
            )
            return
        archive = backup.archive_path
        if not Path(archive).is_file():
            self.set_status(
                self.restore_request_status,
                False,
                "The selected backup file does not exist.",
            )
            return
        try:
            request_id = create_recovery_request(
                self.username,
                archive,
                destination,
                backup.custodian_a,
                backup.custodian_b,
                reason,
                backup_id=backup_id,
            )
            self.logger.info("Recovery request created: %s", request_id)
            self.request_reason.clear()
            self.set_status(
                self.restore_request_status,
                True,
                f"Request #{request_id} sent to both custodians.",
            )
            self.refresh_requests()
            self.refresh_dashboard()
        except (OSError, sqlite3.Error, ValueError) as exc:
            record_event(
                "recovery_request",
                "failure",
                f"operator={self.username}; {exc}",
            )
            self.logger.warning("Could not create recovery request: %s", exc)
            self.set_status(self.restore_request_status, False, str(exc))

    def refresh_requests(self) -> None:
        try:
            requests = get_recovery_requests(self.username)
            self.current_requests = requests
            if self.role == "operator":
                self._populate_request_list(self.operator_request_list, requests)
                if self.operator_request_list.count():
                    self.operator_request_list.setCurrentRow(0)
            elif self.role == "custodian":
                pending = [
                    request
                    for request in requests
                    if request.status in ("pending", "a_approved", "b_approved")
                    and (
                        (
                            request.custodian_a.casefold() == self.username.casefold()
                            and request.custodian_a_approved_at is None
                        )
                        or (
                            request.custodian_b.casefold() == self.username.casefold()
                            and request.custodian_b_approved_at is None
                        )
                    )
                ]
                self._populate_request_list(self.approval_list, pending)
                if self.approval_list.count():
                    self.approval_list.setCurrentRow(0)
        except (OSError, sqlite3.Error) as exc:
            self.logger.error("Could not load recovery requests: %s", exc)
            target = (
                self.restore_request_status
                if self.role == "operator"
                else self.approval_status
            )
            self.set_status(target, False, "Could not load recovery requests.")

    @staticmethod
    def _populate_request_list(
        widget: QListWidget,
        requests: list[RecoveryRequest],
    ) -> None:
        widget.clear()
        for request in requests:
            backup_label = (
                f"BK{request.backup_id:03d}"
                if request.backup_id is not None
                else Path(request.archive_path).name
            )
            item = QListWidgetItem(
                f"Request #{request.request_id} · {request.status.replace('_', ' ').title()}"
                f"\n{backup_label} — {request.reason}"
                f"\nCustodians: {request.custodian_a} and {request.custodian_b}"
            )
            item.setData(Qt.ItemDataRole.UserRole, request.request_id)
            widget.addItem(item)

    @staticmethod
    def _selected_request_id(widget: QListWidget) -> int | None:
        selected = widget.selectedItems()
        if not selected:
            return None
        return int(selected[0].data(Qt.ItemDataRole.UserRole))

    def approve_selected_request(self) -> None:
        if self.role != "custodian":
            raise PermissionError("Only a custodian can approve recovery.")
        request_id = self._selected_request_id(self.approval_list)
        if request_id is None:
            self.set_status(
                self.approval_status, False, "Select a recovery request first."
            )
            return
        passphrase = self.approval_passphrase.text()
        if not passphrase:
            self.set_status(
                self.approval_status,
                False,
                "Enter your custodian passphrase to unlock your share.",
            )
            return
        try:
            share = approve_recovery_request(
                request_id, self.username, passphrase
            )
            slot = self.custodian_slot
            self.released_shares.setdefault(request_id, {})[slot] = bytearray(share)
            requests = get_recovery_requests(self.username)
            request = next(
                item for item in requests if item.request_id == request_id
            )
            if request.status == "approved":
                message = (
                    "Your approval is recorded. Both custodians have approved; "
                    "the operator can now sign in to restore."
                )
            else:
                message = (
                    "Your approval is recorded. Sign out so the other custodian "
                    "can sign in and approve."
                )
            self.set_status(self.approval_status, True, message)
            self.logger.info(
                "Custodian approved recovery request %s", request_id
            )
            self.approval_passphrase.clear()
            self.refresh_requests()
            self.refresh_approval_history()
            self.refresh_dashboard()
        except (BackupError, OSError, sqlite3.Error, ValueError) as exc:
            record_event(
                "custodian_approval",
                "failure",
                f"request_id={request_id}; custodian={self.username}; {exc}",
            )
            self.logger.warning(
                "Custodian approval failed for request %s: %s", request_id, exc
            )
            self.approval_passphrase.clear()
            self.set_status(self.approval_status, False, str(exc))

    def reject_selected_request(self) -> None:
        if self.role != "custodian":
            raise PermissionError("Only a custodian can reject recovery.")
        request_id = self._selected_request_id(self.approval_list)
        if request_id is None:
            self.set_status(
                self.approval_status, False, "Select a recovery request first."
            )
            return
        reason, accepted = QInputDialog.getText(
            self, "Reject recovery request", "Reason for rejecting this request:"
        )
        if not accepted:
            return
        try:
            reject_recovery_request(request_id, self.username, reason)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.set_status(self.approval_status, False, str(exc))
            return
        shares = self.released_shares.pop(request_id, {})
        for share in shares.values():
            share[:] = b"\x00" * len(share)
        self.set_status(self.approval_status, True, "Recovery request rejected.")
        self.refresh_requests()
        self.refresh_approval_history()
        self.refresh_dashboard()

    def restore_approved_request(self) -> None:
        if self.role != "operator":
            raise PermissionError("Only an operator can restore a backup.")
        request_id = self._selected_request_id(self.operator_request_list)
        if request_id is None:
            self.set_status(
                self.operator_restore_status,
                False,
                "Select a recovery request first.",
            )
            return
        self.restore_result_table.setRowCount(0)
        try:
            requests = get_recovery_requests(self.username)
            request = next(
                item for item in requests if item.request_id == request_id
            )
        except (OSError, sqlite3.Error, StopIteration) as exc:
            self.logger.error("Could not load recovery request %s: %s", request_id, exc)
            self.set_status(
                self.operator_restore_status,
                False,
                "Could not load the selected recovery request.",
            )
            return
        if request.status != "approved":
            self.set_status(
                self.operator_restore_status,
                False,
                "Both custodians must approve before the backup can be restored.",
            )
            return
        shares = self.released_shares.get(request_id, {})
        if "A" not in shares or "B" not in shares:
            self.set_status(
                self.operator_restore_status,
                False,
                "Both custodians must approve in this SecureVault session before restoring.",
            )
            return

        answer = QMessageBox.question(
            self,
            "Confirm restore",
            f"Restore request #{request_id} to:\n{request.destination_path}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            result = restore_backup(
                Path(request.archive_path),
                Path(request.destination_path),
                bytes(shares["A"]),
                bytes(shares["B"]),
            )
        except (BackupError, OSError, ValueError) as exc:
            self.logger.error("Restore failed for request %s: %s", request_id, exc)
            try:
                complete_recovery_request(
                    self.username, request_id, False, str(exc)
                )
            except (OSError, sqlite3.Error, ValueError) as status_error:
                self.logger.error(
                    "Could not record failed recovery %s: %s",
                    request_id,
                    status_error,
                )
                message = f"{exc}\nCould not record the failure status."
            else:
                message = str(exc)
            self.set_status(self.operator_restore_status, False, message)
            self.refresh_requests()
            self.refresh_dashboard()
            return
        finally:
            for share in shares.values():
                share[:] = b"\x00" * len(share)
            self.released_shares.pop(request_id, None)

        verified_files = result.get("verified_files", [])
        if not isinstance(verified_files, list):
            verified_files = []
        self.restore_result_table.setRowCount(len(verified_files))
        for row, item in enumerate(verified_files):
            if not isinstance(item, dict):
                continue
            values = (
                str(item.get("path", "")),
                self.format_size(int(item.get("size", 0))),
                str(item.get("sha256", "")),
                str(item.get("status", "Passed")),
            )
            for column, value in enumerate(values):
                self.restore_result_table.setItem(
                    row, column, QTableWidgetItem(value)
                )
        details = f"{result['restored_file_count']} files restored"
        try:
            complete_recovery_request(
                self.username, request_id, True, details
            )
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.logger.error(
                "Restore finished but its result could not be recorded: %s", exc
            )
            self.set_status(
                self.operator_restore_status,
                False,
                f"Restore completed, but its result could not be recorded: {exc}",
            )
            return
        self.logger.info("Restore completed for request %s", request_id)
        self.set_status(
            self.operator_restore_status,
            True,
            f"Restore complete. {details.capitalize()} to {result['destination']}.",
        )
        self.refresh_requests()
        self.refresh_dashboard()

    @staticmethod
    def set_status(label: QLabel, success: bool, message: str) -> None:
        label.setText(message)
        label.setStyleSheet(
            f"color: {GREEN if success else RED}; padding-top: 4px;"
        )


def main() -> int:
    app = QApplication(sys.argv)
    window = SecureVaultApp()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
