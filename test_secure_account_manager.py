"""Security and functionality tests for the hardened account manager."""

import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from uuid import uuid4

from secure_account_manager import AccountManager, ValidationError


class AccountManagerSecurityTests(unittest.TestCase):
    def setUp(self):
        runtime_directory = Path(__file__).with_name(".test_runtime")
        runtime_directory.mkdir(exist_ok=True)
        self.database_path = runtime_directory / f"test_{uuid4().hex}.db"
        self.manager = AccountManager(self.database_path)
        self.password = "SecurePass123!"

    def tearDown(self):
        self.database_path.unlink(missing_ok=True)

    def test_register_and_authenticate_valid_user(self):
        self.assertTrue(self.manager.register("nida_dev", self.password))
        self.assertTrue(self.manager.authenticate("nida_dev", self.password))

    def test_wrong_password_fails(self):
        self.manager.register("nida_dev", self.password)
        self.assertFalse(self.manager.authenticate("nida_dev", "WrongPassword123!"))

    def test_duplicate_username_is_rejected(self):
        self.assertTrue(self.manager.register("nida_dev", self.password))
        self.assertFalse(self.manager.register("nida_dev", self.password))

    def test_invalid_username_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.manager.register("bad user name", self.password)

    def test_weak_password_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.manager.register("nida_dev", "short")

    def test_password_is_not_stored_as_plaintext(self):
        self.manager.register("nida_dev", self.password)
        with closing(sqlite3.connect(self.database_path)) as connection:
            stored_hash, salt = connection.execute(
                "SELECT password_hash, salt FROM users WHERE username = ?", ("nida_dev",)
            ).fetchone()
        self.assertNotEqual(stored_hash, self.password.encode("utf-8"))
        self.assertEqual(len(salt), 16)

    def test_sql_injection_style_username_does_not_bypass_login(self):
        self.manager.register("nida_dev", self.password)
        self.assertFalse(self.manager.authenticate("' OR '1'='1", "anything"))

    def test_unknown_user_returns_false(self):
        self.assertFalse(self.manager.authenticate("missing_user", self.password))


if __name__ == "__main__":
    unittest.main()
