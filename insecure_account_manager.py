"""Educational example of unsafe patterns. Do not use this file in production."""

import sqlite3


def register_user(connection, username, password):
    """Unsafe: stores plaintext passwords and concatenates SQL."""
    query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
    connection.execute(query)
    connection.commit()


def login_user(connection, username, password):
    """Unsafe: susceptible to SQL injection and reveals internal errors."""
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        return connection.execute(query).fetchone() is not None
    except sqlite3.Error as error:
        print(f"Database error: {error}")
        return False
