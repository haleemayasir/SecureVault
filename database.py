"""SQLite event store for the backup application."""

import hashlib
import hmac
import re
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path


DATABASE_NAME = "backup_system.db"
PASSWORD_HASH_ITERATIONS = 600_000
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{3,32}\Z")


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
    return database


def _hash_password(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )


def register_user(
    username: str,
    password: str,
    base_directory: Path | None = None,
) -> None:
    username = username.strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError(
            "Username must be 3-32 characters: letters, numbers, dot, underscore or hyphen."
        )
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")

    salt = secrets.token_bytes(16)
    password_hash = _hash_password(password, salt, PASSWORD_HASH_ITERATIONS)
    database = initialise_database(base_directory)
    try:
        with closing(sqlite3.connect(database)) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO users(username, salt, password_hash, iterations)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, salt, password_hash, PASSWORD_HASH_ITERATIONS),
                )
    except sqlite3.IntegrityError as exc:
        raise ValueError("That username is already registered.") from exc


def authenticate_user(
    username: str,
    password: str,
    base_directory: Path | None = None,
) -> bool:
    database = initialise_database(base_directory)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            row = connection.execute(
                """
                SELECT salt, password_hash, iterations
                FROM users
                WHERE username = ? COLLATE NOCASE
                """,
                (username.strip(),),
            ).fetchone()

    if row is None:
        return False
    salt, stored_hash, iterations = row
    candidate_hash = _hash_password(password, salt, iterations)
    return hmac.compare_digest(candidate_hash, stored_hash)


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
