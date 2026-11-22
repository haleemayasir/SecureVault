"""SQLite accounts, recovery approvals, and activity storage."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from custodian_keys import (
    create_custodian_identity,
    decrypt_custodian_share,
    validate_legacy_custodian_passphrase,
)


DATABASE_NAME = "backup_system.db"
PASSWORD_HASH_ITERATIONS = 600_000
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{3,32}\Z")


@dataclass(frozen=True)
class RecoveryRequest:
    request_id: int
    created_at: str
    created_by: str
    archive_path: str
    destination_path: str
    custodian_a: str
    custodian_b: str
    reason: str
    status: str
    custodian_a_approved_at: str | None
    custodian_b_approved_at: str | None
    custodian_a_share_path: str | None
    custodian_b_share_path: str | None
    result_details: str | None
    backup_id: int | None


@dataclass(frozen=True)
class ActivityEvent:
    created_at: str
    action: str
    outcome: str
    details: str


@dataclass(frozen=True)
class BackupRecord:
    backup_id: int
    name: str
    created_at: str
    archive_path: str
    archive_sha256: str
    file_count: int
    size_bytes: int
    custodian_a: str
    custodian_b: str
    share_a_path: str
    share_b_path: str
    share_a_sha256: str
    share_b_sha256: str
    share_a_envelope: bytes | None
    share_b_envelope: bytes | None
    file_manifest: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class CustodianAccount:
    slot: str | None
    username: str
    is_active: bool
    must_change_password: bool
    created_at: str


@dataclass(frozen=True)
class CustodianKeyAssignment:
    backup_id: int
    backup_name: str
    created_at: str
    slot: str


def get_database_path(base_directory: Path | None = None) -> Path:
    base = base_directory or Path(__file__).resolve().parent
    return base / DATABASE_NAME


def initialise_database(base_directory: Path | None = None) -> Path:
    database = get_database_path(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    iterations INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(users)")
            }
            if "role" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'operator'"
                )
            if "must_change_password" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"
                )
            if "custodian_slot" not in columns:
                connection.execute("ALTER TABLE users ADD COLUMN custodian_slot TEXT")
            if "is_active" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"
                )
            if "custodian_key_salt" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN custodian_key_salt BLOB"
                )
            if "custodian_public_key" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN custodian_public_key BLOB"
                )
            if "custodian_private_key" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN custodian_private_key BLOB"
                )
            if "legacy_custodian_public_key" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN legacy_custodian_public_key BLOB"
                )
            connection.execute(
                """
                UPDATE users
                SET legacy_custodian_public_key = custodian_public_key
                WHERE custodian_key_salt IS NOT NULL
                  AND custodian_public_key IS NOT NULL
                  AND custodian_private_key IS NULL
                  AND legacy_custodian_public_key IS NULL
                """
            )
            assigned_slots = {
                str(row[0])
                for row in connection.execute(
                    "SELECT custodian_slot FROM users WHERE custodian_slot IS NOT NULL"
                )
            }
            available_slots = [
                slot for slot in ("A", "B") if slot not in assigned_slots
            ]
            legacy_custodians = connection.execute(
                """
                SELECT username FROM users
                WHERE role = 'custodian' AND custodian_slot IS NULL
                ORDER BY created_at, rowid
                """
            ).fetchall()
            for slot, row in zip(available_slots, legacy_custodians):
                connection.execute(
                    "UPDATE users SET custodian_slot = ? WHERE username = ?",
                    (slot, row[0]),
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS recovery_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    created_by TEXT NOT NULL,
                    archive_path TEXT NOT NULL,
                    destination_path TEXT NOT NULL,
                    custodian_a TEXT NOT NULL,
                    custodian_b TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    custodian_a_approved_at TEXT,
                    custodian_b_approved_at TEXT,
                    custodian_a_share_path TEXT,
                    custodian_b_share_path TEXT,
                    result_details TEXT
                )
                """
            )
            request_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(recovery_requests)"
                )
            }
            if "backup_id" not in request_columns:
                connection.execute(
                    "ALTER TABLE recovery_requests ADD COLUMN backup_id INTEGER"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS backups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    archive_path TEXT NOT NULL,
                    archive_sha256 TEXT NOT NULL,
                    file_count INTEGER NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    custodian_a TEXT NOT NULL,
                    custodian_b TEXT NOT NULL,
                    share_a_path TEXT NOT NULL,
                    share_b_path TEXT NOT NULL,
                    share_a_sha256 TEXT NOT NULL DEFAULT '',
                    share_b_sha256 TEXT NOT NULL DEFAULT '',
                    share_a_envelope BLOB,
                    share_b_envelope BLOB,
                    file_manifest TEXT NOT NULL
                )
                """
            )
            backup_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(backups)")
            }
            if "share_a_sha256" not in backup_columns:
                connection.execute(
                    "ALTER TABLE backups ADD COLUMN share_a_sha256 TEXT NOT NULL DEFAULT ''"
                )
            if "share_b_sha256" not in backup_columns:
                connection.execute(
                    "ALTER TABLE backups ADD COLUMN share_b_sha256 TEXT NOT NULL DEFAULT ''"
                )
            if "share_a_envelope" not in backup_columns:
                connection.execute("ALTER TABLE backups ADD COLUMN share_a_envelope BLOB")
            if "share_b_envelope" not in backup_columns:
                connection.execute("ALTER TABLE backups ADD COLUMN share_b_envelope BLOB")
    return database


def _validated_credentials(username: str, password: str) -> tuple[str, bytes, bytes]:
    username = username.strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError(
            "Username must be 3-32 characters: letters, numbers, dot, underscore or hyphen."
        )
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    salt = secrets.token_bytes(16)
    password_hash = _hash_password(password, salt, PASSWORD_HASH_ITERATIONS)
    return username, salt, password_hash


def _hash_password(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )


def user_count(base_directory: Path | None = None) -> int:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute("SELECT COUNT(*) FROM users").fetchone()
    return int(row[0])


def get_user_role(
    username: str,
    base_directory: Path | None = None,
) -> str | None:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT role FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()
    return str(row[0]) if row else None


def register_user(
    username: str,
    password: str,
    base_directory: Path | None = None,
) -> None:
    username, salt, password_hash = _validated_credentials(username, password)
    database = initialise_database(base_directory)
    try:
        with closing(sqlite3.connect(database)) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM users LIMIT 1"
                ).fetchone():
                    raise ValueError(
                        "Initial setup is complete. Ask an operator to create your account."
                    )
                connection.execute(
                    """
                    INSERT INTO users(username, salt, password_hash, iterations, role)
                    VALUES (?, ?, ?, ?, 'operator')
                    """,
                    (username, salt, password_hash, PASSWORD_HASH_ITERATIONS),
                )
    except sqlite3.IntegrityError as exc:
        raise ValueError("That username is already registered.") from exc


def create_custodian_user(
    created_by: str,
    username: str,
    password: str,
    base_directory: Path | None = None,
    slot: str | None = None,
) -> None:
    if slot not in ("A", "B"):
        raise ValueError("Choose Custodian A or Custodian B.")
    username, salt, password_hash = _validated_credentials(username, password)
    database = initialise_database(base_directory)
    try:
        with closing(sqlite3.connect(database)) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                operator = connection.execute(
                    """
                    SELECT role FROM users
                    WHERE username = ? COLLATE NOCASE
                    """,
                    (created_by.strip(),),
                ).fetchone()
                if operator is None or operator[0] != "operator":
                    raise ValueError("Only an operator can create custodian accounts.")
                occupied = connection.execute(
                    """
                    SELECT username FROM users
                    WHERE role = 'custodian' AND custodian_slot = ?
                    """,
                    (slot,),
                ).fetchone()
                if occupied is not None:
                    raise ValueError(f"Custodian {slot} already has an account.")
                connection.execute(
                    """
                    INSERT INTO users(
                        username, salt, password_hash, iterations, role,
                        must_change_password, custodian_slot
                    ) VALUES (?, ?, ?, ?, 'custodian', 1, ?)
                    """,
                    (username, salt, password_hash, PASSWORD_HASH_ITERATIONS, slot),
                )
    except sqlite3.IntegrityError as exc:
        raise ValueError("That username is already registered.") from exc


def list_custodians(base_directory: Path | None = None) -> list[str]:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(
            """
            SELECT username FROM users
            WHERE role = 'custodian' AND must_change_password = 0
              AND is_active = 1
            ORDER BY custodian_slot
            """
        ).fetchall()
    return [str(row[0]) for row in rows]


def get_custodian_accounts(
    base_directory: Path | None = None,
) -> list[CustodianAccount]:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(
            """
            SELECT custodian_slot, username, is_active,
                   must_change_password, created_at
            FROM users
            WHERE role = 'custodian'
            ORDER BY CASE custodian_slot WHEN 'A' THEN 0 WHEN 'B' THEN 1 ELSE 2 END,
                     username COLLATE NOCASE
            """
        ).fetchall()
    return [
        CustodianAccount(
            slot=str(row[0]) if row[0] is not None else None,
            username=str(row[1]),
            is_active=bool(row[2]),
            must_change_password=bool(row[3]),
            created_at=str(row[4]),
        )
        for row in rows
    ]


def has_custodian_key(
    username: str,
    base_directory: Path | None = None,
) -> bool:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            """
            SELECT role, custodian_private_key, custodian_public_key
            FROM users WHERE username = ? COLLATE NOCASE
            """,
            (username.strip(),),
        ).fetchone()
    return bool(row and row[0] == "custodian" and row[1] and row[2])


def get_custodian_public_identity(
    slot: str,
    base_directory: Path | None = None,
) -> tuple[str, bytes] | None:
    if slot not in ("A", "B"):
        raise ValueError("Custodian slot must be A or B.")
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            """
            SELECT username, custodian_public_key
            FROM users
            WHERE role = 'custodian' AND custodian_slot = ?
              AND is_active = 1 AND must_change_password = 0
              AND custodian_private_key IS NOT NULL
              AND custodian_public_key IS NOT NULL
            """,
            (slot,),
        ).fetchone()
    if row is None:
        return None
    return str(row[0]), bytes(row[1])


def get_custodian_key_assignments(
    username: str,
    base_directory: Path | None = None,
) -> list[CustodianKeyAssignment]:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        account = connection.execute(
            """
            SELECT role FROM users WHERE username = ? COLLATE NOCASE
            """,
            (username.strip(),),
        ).fetchone()
        if account is None or account["role"] != "custodian":
            raise ValueError("Only a custodian can view assigned recovery shares.")
        rows = connection.execute(
            """
            SELECT id, name, created_at, 'A' AS slot
            FROM backups
            WHERE custodian_a = ? COLLATE NOCASE AND share_a_envelope IS NOT NULL
            UNION ALL
            SELECT id, name, created_at, 'B' AS slot
            FROM backups
            WHERE custodian_b = ? COLLATE NOCASE AND share_b_envelope IS NOT NULL
            ORDER BY id DESC
            """,
            (username.strip(), username.strip()),
        ).fetchall()
    return [
        CustodianKeyAssignment(
            backup_id=int(row["id"]),
            backup_name=str(row["name"]),
            created_at=str(row["created_at"]),
            slot=str(row["slot"]),
        )
        for row in rows
    ]


def initialize_custodian_key(
    username: str,
    passphrase: str,
    base_directory: Path | None = None,
) -> None:
    encrypted_private_key, public_key = create_custodian_identity(passphrase)
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            account = connection.execute(
                """
                SELECT role, is_active, must_change_password,
                       custodian_private_key, custodian_key_salt,
                       custodian_public_key, legacy_custodian_public_key
                FROM users WHERE username = ? COLLATE NOCASE
                """,
                (username.strip(),),
            ).fetchone()
            if (
                account is None
                or account[0] != "custodian"
                or not account[1]
                or account[2]
            ):
                raise ValueError(
                    "Sign in with an active custodian account and set its login password first."
                )
            if account[3] is not None:
                raise ValueError("This custodian key is already initialized.")
            if account[4] is not None and account[6] is not None:
                if not validate_legacy_custodian_passphrase(
                    passphrase, bytes(account[4]), bytes(account[6])
                ):
                    raise ValueError(
                        "Use your existing recovery passphrase to preserve access to older backups."
                    )
            connection.execute(
                """
                UPDATE users
                SET custodian_private_key = ?, custodian_public_key = ?
                WHERE username = ? COLLATE NOCASE
                """,
                (encrypted_private_key, public_key, username.strip()),
            )
    record_event(
        "custodian_key_setup",
        "success",
        f"custodian={username.strip()}",
        base_directory,
    )


def clear_volatile_recovery_approvals(
    base_directory: Path | None = None,
) -> int:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            cursor = connection.execute(
                """
                UPDATE recovery_requests
                SET status = 'pending',
                    custodian_a_approved_at = NULL,
                    custodian_b_approved_at = NULL,
                    custodian_a_share_path = NULL,
                    custodian_b_share_path = NULL,
                    result_details = NULL
                WHERE status IN ('a_approved', 'b_approved', 'approved')
                """
            )
            count = cursor.rowcount
    if count:
        record_event(
            "recovery_approval_reset",
            "success",
            f"count={count}; reason=volatile shares cleared at startup",
            base_directory,
        )
    return count


def create_backup_record(
    created_by: str,
    name: str,
    archive_path: str,
    archive_sha256: str,
    file_count: int,
    size_bytes: int,
    custodian_a_envelope: bytes,
    custodian_b_envelope: bytes,
    file_manifest: list[dict[str, object]],
    base_directory: Path | None = None,
) -> int:
    values = (
        name.strip(),
        archive_path.strip(),
        archive_sha256.strip(),
    )
    if not all(values):
        raise ValueError("Complete the backup name and archive path.")
    if not custodian_a_envelope or not custodian_b_envelope:
        raise ValueError("Both custodian recovery shares must be encrypted.")
    if file_count < 0 or size_bytes < 0:
        raise ValueError("Backup file counts and sizes cannot be negative.")
    if file_count != len(file_manifest):
        raise ValueError("The backup file count does not match its manifest.")
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            creator = connection.execute(
                "SELECT role FROM users WHERE username = ? COLLATE NOCASE",
                (created_by.strip(),),
            ).fetchone()
            if creator is None or creator[0] != "operator":
                raise ValueError("Only an operator can catalog a backup.")
            custodians: dict[str, str] = {}
            for slot in ("A", "B"):
                row = connection.execute(
                    """
                    SELECT username, custodian_public_key FROM users
                    WHERE role = 'custodian' AND custodian_slot = ?
                      AND is_active = 1 AND must_change_password = 0
                      AND custodian_private_key IS NOT NULL
                      AND custodian_public_key IS NOT NULL
                    """,
                    (slot,),
                ).fetchone()
                if row is None:
                    raise ValueError(
                        f"Create and activate Custodian {slot} before creating backups."
                    )
                custodians[slot] = str(row[0])
            cursor = connection.execute(
                """
                INSERT INTO backups(
                    name, archive_path, archive_sha256, file_count, size_bytes,
                    custodian_a, custodian_b, share_a_path, share_b_path,
                    share_a_sha256, share_b_sha256, share_a_envelope,
                    share_b_envelope, file_manifest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, '', '', '', '', ?, ?, ?)
                """,
                (
                    values[0],
                    values[1],
                    values[2],
                    file_count,
                    size_bytes,
                    custodians["A"],
                    custodians["B"],
                    custodian_a_envelope,
                    custodian_b_envelope,
                    json.dumps(file_manifest, sort_keys=True),
                ),
            )
            backup_id = int(cursor.lastrowid)
    record_event(
        "create_backup",
        "success",
        f"backup_id={backup_id}; name={values[0]}; archive={Path(values[1]).name}; files={file_count}",
        base_directory,
    )
    return backup_id


def _backup_record(row: sqlite3.Row) -> BackupRecord:
    manifest = json.loads(row["file_manifest"])
    if not isinstance(manifest, list):
        raise ValueError("Stored backup manifest is malformed.")
    return BackupRecord(
        backup_id=int(row["id"]),
        name=str(row["name"]),
        created_at=str(row["created_at"]),
        archive_path=str(row["archive_path"]),
        archive_sha256=str(row["archive_sha256"]),
        file_count=int(row["file_count"]),
        size_bytes=int(row["size_bytes"]),
        custodian_a=str(row["custodian_a"]),
        custodian_b=str(row["custodian_b"]),
        share_a_path=str(row["share_a_path"]),
        share_b_path=str(row["share_b_path"]),
        share_a_sha256=str(row["share_a_sha256"]),
        share_b_sha256=str(row["share_b_sha256"]),
        share_a_envelope=(
            bytes(row["share_a_envelope"])
            if row["share_a_envelope"] is not None
            else None
        ),
        share_b_envelope=(
            bytes(row["share_b_envelope"])
            if row["share_b_envelope"] is not None
            else None
        ),
        file_manifest=tuple(manifest),
    )


def get_backups(base_directory: Path | None = None) -> list[BackupRecord]:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM backups ORDER BY id DESC").fetchall()
    return [_backup_record(row) for row in rows]


def get_backup_record(
    backup_id: int,
    base_directory: Path | None = None,
) -> BackupRecord | None:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM backups WHERE id = ?", (backup_id,)
        ).fetchone()
    return _backup_record(row) if row is not None else None


def get_recent_activity(
    limit: int = 7,
    base_directory: Path | None = None,
) -> list[ActivityEvent]:
    if not 1 <= limit <= 100:
        raise ValueError("Activity limit must be between 1 and 100.")
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(
            """
            SELECT created_at, action, outcome, details
            FROM activity
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        ActivityEvent(
            created_at=str(row[0]),
            action=str(row[1]),
            outcome=str(row[2]),
            details=str(row[3] or ""),
        )
        for row in rows
    ]


def get_latest_backup(
    base_directory: Path | None = None,
) -> ActivityEvent | None:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            """
            SELECT created_at, action, outcome, details
            FROM activity
            WHERE action = 'create_backup' AND outcome = 'success'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    if row is None:
        return None
    return ActivityEvent(
        created_at=str(row[0]),
        action=str(row[1]),
        outcome=str(row[2]),
        details=str(row[3] or ""),
    )


def authenticate_user(
    username: str,
    password: str,
    base_directory: Path | None = None,
) -> bool:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            """
            SELECT salt, password_hash, iterations
            FROM users
            WHERE username = ? COLLATE NOCASE AND is_active = 1
            """,
            (username.strip(),),
        ).fetchone()

    if row is None:
        return False
    salt, stored_hash, iterations = row
    candidate_hash = _hash_password(password, salt, iterations)
    return hmac.compare_digest(candidate_hash, stored_hash)


def password_change_required(
    username: str,
    base_directory: Path | None = None,
) -> bool:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            """
            SELECT must_change_password
            FROM users
            WHERE username = ? COLLATE NOCASE
            """,
            (username.strip(),),
        ).fetchone()
    return bool(row[0]) if row else False


def change_user_password(
    username: str,
    current_password: str,
    new_password: str,
    base_directory: Path | None = None,
) -> None:
    username, salt, password_hash = _validated_credentials(username, new_password)
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT salt, password_hash, iterations
                FROM users
                WHERE username = ? COLLATE NOCASE
                """,
                (username,),
            ).fetchone()
            if row is None:
                raise ValueError("Current password is incorrect.")
            old_salt, stored_hash, old_iterations = row
            current_hash = _hash_password(
                current_password, old_salt, old_iterations
            )
            if not hmac.compare_digest(current_hash, stored_hash):
                raise ValueError("Current password is incorrect.")
            new_password_hash = _hash_password(
                new_password, old_salt, old_iterations
            )
            if hmac.compare_digest(new_password_hash, stored_hash):
                raise ValueError("Choose a password different from the current password.")
            connection.execute(
                """
                UPDATE users
                SET salt = ?, password_hash = ?, iterations = ?,
                    must_change_password = 0
                WHERE username = ? COLLATE NOCASE
                """,
                (salt, password_hash, PASSWORD_HASH_ITERATIONS, username),
            )
    record_event("password_changed", "success", f"username={username}", base_directory)


def reset_custodian_password(
    operator_username: str,
    custodian_username: str,
    temporary_password: str,
    base_directory: Path | None = None,
) -> None:
    username, salt, password_hash = _validated_credentials(
        custodian_username, temporary_password
    )
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            operator = connection.execute(
                "SELECT role FROM users WHERE username = ? COLLATE NOCASE",
                (operator_username.strip(),),
            ).fetchone()
            if operator is None or operator[0] != "operator":
                raise ValueError("Only an operator can reset custodian access.")
            cursor = connection.execute(
                """
                UPDATE users
                SET salt = ?, password_hash = ?, iterations = ?,
                    must_change_password = 1
                WHERE username = ? COLLATE NOCASE AND role = 'custodian'
                """,
                (salt, password_hash, PASSWORD_HASH_ITERATIONS, username),
            )
            if cursor.rowcount != 1:
                raise ValueError("Select an existing custodian account.")
    record_event(
        "custodian_credential_reset",
        "success",
        f"operator={operator_username.strip()}; custodian={username}",
        base_directory,
    )


def set_custodian_active(
    operator_username: str,
    custodian_username: str,
    is_active: bool,
    base_directory: Path | None = None,
) -> None:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            operator = connection.execute(
                "SELECT role FROM users WHERE username = ? COLLATE NOCASE",
                (operator_username.strip(),),
            ).fetchone()
            if operator is None or operator[0] != "operator":
                raise ValueError("Only an operator can manage custodian accounts.")
            custodian = connection.execute(
                """
                SELECT username FROM users
                WHERE username = ? COLLATE NOCASE AND role = 'custodian'
                """,
                (custodian_username.strip(),),
            ).fetchone()
            if custodian is None:
                raise ValueError("Select an existing custodian account.")
            if not is_active:
                pending = connection.execute(
                    """
                    SELECT 1 FROM recovery_requests
                    WHERE status IN ('pending', 'a_approved', 'b_approved', 'approved')
                      AND (custodian_a = ? COLLATE NOCASE
                           OR custodian_b = ? COLLATE NOCASE)
                    LIMIT 1
                    """,
                    (custodian_username.strip(), custodian_username.strip()),
                ).fetchone()
                if pending is not None:
                    raise ValueError(
                        "This custodian has an open recovery request and cannot be deactivated."
                    )
            connection.execute(
                "UPDATE users SET is_active = ? WHERE username = ? COLLATE NOCASE",
                (int(is_active), custodian_username.strip()),
            )
    outcome = "activated" if is_active else "deactivated"
    record_event(
        "custodian_account",
        outcome,
        f"operator={operator_username.strip()}; custodian={custodian_username.strip()}",
        base_directory,
    )


def get_user_profile(
    username: str,
    base_directory: Path | None = None,
) -> dict[str, str] | None:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            """
            SELECT username, role, custodian_slot, created_at, is_active
            FROM users WHERE username = ? COLLATE NOCASE
            """,
            (username.strip(),),
        ).fetchone()
    if row is None:
        return None
    return {
        "username": str(row[0]),
        "role": str(row[1]),
        "custodian_slot": str(row[2]) if row[2] is not None else "",
        "created_at": str(row[3]),
        "is_active": "Active" if row[4] else "Inactive",
    }


def create_recovery_request(
    created_by: str,
    archive_path: str,
    destination_path: str,
    custodian_a: str,
    custodian_b: str,
    reason: str,
    base_directory: Path | None = None,
    backup_id: int | None = None,
) -> int:
    values = (
        archive_path.strip(),
        destination_path.strip(),
        custodian_a.strip(),
        custodian_b.strip(),
        reason.strip(),
    )
    if not all(values):
        raise ValueError("Complete the backup, destination, custodian, and reason fields.")
    archive, destination, name_a, name_b, request_reason = values
    if name_a.casefold() == name_b.casefold():
        raise ValueError("Choose two different custodians.")

    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            creator = connection.execute(
                "SELECT role, is_active FROM users WHERE username = ? COLLATE NOCASE",
                (created_by.strip(),),
            ).fetchone()
            if creator is None or creator[0] != "operator" or not creator[1]:
                raise ValueError("Only an operator can request a recovery.")
            actual_names: list[str] = []
            for name, slot in ((name_a, "A"), (name_b, "B")):
                custodian = connection.execute(
                    """
                    SELECT username, custodian_slot FROM users
                    WHERE username = ? COLLATE NOCASE
                      AND role = 'custodian'
                      AND must_change_password = 0
                      AND is_active = 1
                    """,
                    (name,),
                ).fetchone()
                if custodian is None or custodian[1] != slot:
                    raise ValueError(
                        f"Select the active Custodian {slot} account. The custodian must sign in and set a personal password first."
                    )
                actual_names.append(str(custodian[0]))
            if backup_id is not None:
                backup = connection.execute(
                    """
                    SELECT archive_path, custodian_a, custodian_b,
                           share_a_envelope, share_b_envelope
                    FROM backups WHERE id = ?
                    """,
                    (backup_id,),
                ).fetchone()
                if (
                    backup is None
                    or str(backup[0]) != archive
                    or str(backup[1]).casefold() != actual_names[0].casefold()
                    or str(backup[2]).casefold() != actual_names[1].casefold()
                    or backup[3] is None
                    or backup[4] is None
                ):
                    raise ValueError(
                        "The selected backup has no protected custodian shares or its assignments changed."
                    )
            cursor = connection.execute(
                """
                INSERT INTO recovery_requests (
                    created_by, archive_path, destination_path, custodian_a,
                    custodian_b, reason, backup_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_by.strip(),
                    archive,
                    destination,
                    actual_names[0],
                    actual_names[1],
                    request_reason,
                    backup_id,
                ),
            )
            request_id = int(cursor.lastrowid)
    record_event(
        "recovery_request",
        "pending",
        f"request_id={request_id}; operator={created_by.strip()}",
        base_directory,
    )
    return request_id


def get_recovery_requests(
    username: str,
    base_directory: Path | None = None,
) -> list[RecoveryRequest]:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        account = connection.execute(
            "SELECT role FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()
        if account is None:
            return []
        if account["role"] == "operator":
            rows = connection.execute(
                "SELECT * FROM recovery_requests ORDER BY id DESC"
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM recovery_requests
                WHERE custodian_a = ? COLLATE NOCASE
                   OR custodian_b = ? COLLATE NOCASE
                ORDER BY id DESC
                """,
                (username.strip(), username.strip()),
            ).fetchall()
    return [
        RecoveryRequest(
            request_id=int(row["id"]),
            created_at=str(row["created_at"]),
            created_by=str(row["created_by"]),
            archive_path=str(row["archive_path"]),
            destination_path=str(row["destination_path"]),
            custodian_a=str(row["custodian_a"]),
            custodian_b=str(row["custodian_b"]),
            reason=str(row["reason"]),
            status=str(row["status"]),
            custodian_a_approved_at=row["custodian_a_approved_at"],
            custodian_b_approved_at=row["custodian_b_approved_at"],
            custodian_a_share_path=row["custodian_a_share_path"],
            custodian_b_share_path=row["custodian_b_share_path"],
            result_details=row["result_details"],
            backup_id=(
                int(row["backup_id"])
                if row["backup_id"] is not None
                else None
            ),
        )
        for row in rows
    ]


def approve_recovery_request(
    request_id: int,
    custodian_username: str,
    passphrase: str,
    base_directory: Path | None = None,
) -> bytes:
    if not passphrase:
        raise ValueError("Enter your custodian passphrase.")
    database = initialise_database(base_directory)
    share: bytes
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            user = connection.execute(
                """
                SELECT role, is_active, custodian_slot,
                       custodian_key_salt, custodian_public_key,
                       custodian_private_key, legacy_custodian_public_key
                FROM users WHERE username = ? COLLATE NOCASE
                """,
                (custodian_username.strip(),),
            ).fetchone()
            if user is None or user[0] != "custodian" or not user[1]:
                raise ValueError("Sign in with a custodian account to approve recovery.")
            request = connection.execute(
                "SELECT * FROM recovery_requests WHERE id = ?",
                (request_id,),
            ).fetchone()
            if request is None:
                raise ValueError("This recovery request no longer exists.")
            if request["status"] not in ("pending", "a_approved", "b_approved"):
                raise ValueError("This recovery request is no longer awaiting approval.")

            if str(request["custodian_a"]).casefold() == custodian_username.casefold():
                timestamp_column = "custodian_a_approved_at"
                status_column = "a_approved"
                share_column = "share_a_envelope"
                assigned_slot = "A"
            elif str(request["custodian_b"]).casefold() == custodian_username.casefold():
                timestamp_column = "custodian_b_approved_at"
                status_column = "b_approved"
                share_column = "share_b_envelope"
                assigned_slot = "B"
            else:
                raise ValueError("You are not assigned to this recovery request.")
            if user["custodian_slot"] != assigned_slot:
                raise ValueError(
                    f"This account is not assigned as Custodian {assigned_slot}."
                )
            if (
                user["custodian_public_key"] is None
                or (
                    user["custodian_private_key"] is None
                    and (
                        user["custodian_key_salt"] is None
                        or user["legacy_custodian_public_key"] is None
                    )
                )
            ):
                raise ValueError("Set up your custodian passphrase before approving.")
            if request[timestamp_column] is not None:
                raise ValueError("You have already approved this recovery request.")
            if request["backup_id"] is None:
                raise ValueError(
                    "This legacy backup does not have custodian-encrypted shares. Create a protected backup to recover it."
                )
            backup = connection.execute(
                """
                SELECT archive_sha256, share_a_envelope, share_b_envelope
                FROM backups WHERE id = ?
                """,
                (request["backup_id"],),
            ).fetchone()
            if backup is None or backup[share_column] is None:
                raise ValueError("The protected share for this backup is missing.")
            share = decrypt_custodian_share(
                bytes(backup[share_column]),
                custodian_username,
                assigned_slot,
                str(backup["archive_sha256"]),
                passphrase,
                (
                    bytes(user["custodian_private_key"])
                    if user["custodian_private_key"] is not None
                    else None
                ),
                bytes(user["custodian_public_key"]),
                (
                    bytes(user["custodian_key_salt"])
                    if user["custodian_key_salt"] is not None
                    else None
                ),
                (
                    bytes(user["legacy_custodian_public_key"])
                    if user["legacy_custodian_public_key"] is not None
                    else None
                ),
            )

            connection.execute(
                f"""
                UPDATE recovery_requests
                SET {timestamp_column} = datetime('now'),
                    status = CASE
                        WHEN {'custodian_b_approved_at' if timestamp_column == 'custodian_a_approved_at' else 'custodian_a_approved_at'} IS NOT NULL
                        THEN 'approved'
                        ELSE ?
                    END
                WHERE id = ?
                """,
                (status_column, request_id),
            )
            status = connection.execute(
                "SELECT status FROM recovery_requests WHERE id = ?",
                (request_id,),
            ).fetchone()[0]
    record_event(
        "custodian_approval",
        str(status),
        f"request_id={request_id}; custodian={custodian_username.strip()}",
        base_directory,
    )
    return share


def reject_recovery_request(
    request_id: int,
    custodian_username: str,
    reason: str,
    base_directory: Path | None = None,
) -> None:
    rejection_reason = reason.strip()
    if not rejection_reason:
        raise ValueError("Enter a reason for rejecting this recovery request.")
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            user = connection.execute(
                """
                SELECT role, is_active FROM users
                WHERE username = ? COLLATE NOCASE
                """,
                (custodian_username.strip(),),
            ).fetchone()
            if user is None or user[0] != "custodian" or not user[1]:
                raise ValueError("Sign in with an active custodian account.")
            request = connection.execute(
                "SELECT * FROM recovery_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if request is None:
                raise ValueError("This recovery request no longer exists.")
            if custodian_username.casefold() not in (
                str(request[5]).casefold(),
                str(request[6]).casefold(),
            ):
                raise ValueError("You are not assigned to this recovery request.")
            if request[8] not in ("pending", "a_approved", "b_approved"):
                raise ValueError("This recovery request is no longer awaiting a decision.")
            connection.execute(
                """
                UPDATE recovery_requests
                SET status = 'rejected', result_details = ?
                WHERE id = ?
                """,
                (rejection_reason, request_id),
            )
    record_event(
        "custodian_rejection",
        "rejected",
        f"request_id={request_id}; custodian={custodian_username.strip()}; reason={rejection_reason}",
        base_directory,
    )


def complete_recovery_request(
    operator_username: str,
    request_id: int,
    succeeded: bool,
    details: str,
    base_directory: Path | None = None,
) -> None:
    database = initialise_database(base_directory)
    status = "completed" if succeeded else "failed"
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            account = connection.execute(
                "SELECT role FROM users WHERE username = ? COLLATE NOCASE",
                (operator_username.strip(),),
            ).fetchone()
            if account is None or account[0] != "operator":
                raise ValueError("Only an operator can complete a recovery.")
            cursor = connection.execute(
                """
                UPDATE recovery_requests
                SET status = ?, result_details = ?
                WHERE id = ? AND status = 'approved'
                """,
                (status, details, request_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Recovery must have both approvals before it can finish.")
    record_event(
        "restore_backup",
        status,
        f"request_id={request_id}; operator={operator_username.strip()}; {details}",
        base_directory,
    )


def record_event(
    action: str,
    outcome: str,
    details: str = "",
    base_directory: Path | None = None,
) -> None:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute(
                "INSERT INTO activity(action, outcome, details) VALUES (?, ?, ?)",
                (action, outcome, details),
            )
