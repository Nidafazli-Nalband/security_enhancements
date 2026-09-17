"""A small CLI-compatible account manager demonstrating secure Python practices."""

from __future__ import annotations

import getpass
import hashlib
import hmac
import re
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path


PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_DUMMY_SALT = b"security-demo-salt"
_DUMMY_HASH = hashlib.pbkdf2_hmac("sha256", b"password", _DUMMY_SALT, PBKDF2_ITERATIONS)


class ValidationError(ValueError):
    """Raised when registration input does not meet validation rules."""


class AccountManager:
    """Store account credentials in SQLite without retaining plaintext passwords."""

    def __init__(self, database_path: str | Path = "accounts.db") -> None:
        self.database_path = str(database_path)
        self.initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize_database(self) -> None:
        """Create the database table when it does not exist."""
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash BLOB NOT NULL,
                        salt BLOB NOT NULL
                    )
                    """
                )

    @staticmethod
    def validate_username(username: str) -> str:
        if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
            raise ValidationError(
                "Username must contain 3 to 32 letters, numbers, dots, hyphens, or underscores."
            )
        return username

    @staticmethod
    def validate_password(password: str) -> str:
        if not isinstance(password, str):
            raise ValidationError("Password must be text.")
        if len(password) < 12:
            raise ValidationError("Password must contain at least 12 characters.")
        categories = sum(
            [
                any(character.islower() for character in password),
                any(character.isupper() for character in password),
                any(character.isdigit() for character in password),
                any(not character.isalnum() for character in password),
            ]
        )
        if categories < 3:
            raise ValidationError("Password must use at least three character categories.")
        return password

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)

    def register(self, username: str, password: str) -> bool:
        """Register a user safely. False means that username is unavailable."""
        username = self.validate_username(username)
        password = self.validate_password(password)
        salt = secrets.token_bytes(SALT_BYTES)
        password_hash = self._hash_password(password, salt)
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                        (username, password_hash, salt),
                    )
            return True
        except sqlite3.IntegrityError:
            return False

    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate without exposing whether a username exists."""
        if not isinstance(username, str) or not isinstance(password, str):
            return False
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT password_hash, salt FROM users WHERE username = ?", (username,)
            ).fetchone()
        if row is None:
            # Perform a comparable password operation for a missing account.
            supplied_hash = self._hash_password(password, _DUMMY_SALT)
            return hmac.compare_digest(supplied_hash, _DUMMY_HASH) and False
        stored_hash, salt = row
        supplied_hash = self._hash_password(password, salt)
        return hmac.compare_digest(stored_hash, supplied_hash)


def main() -> None:
    """Run a minimal local CLI without echoing password input."""
    manager = AccountManager()
    action = input("Choose register or login: ").strip().lower()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    try:
        if action == "register":
            print("Registration completed." if manager.register(username, password) else "Registration failed.")
        elif action == "login":
            print("Login successful." if manager.authenticate(username, password) else "Invalid credentials.")
        else:
            print("Invalid action.")
    except ValidationError as error:
        print(f"Input error: {error}")


if __name__ == "__main__":
    main()
