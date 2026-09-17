# Week 5 Security Audit Report

## Scope

This audit compares an educational insecure example with a hardened local SQLite account manager. The insecure file is included only to document the risks and must not be used in production.

## Findings and Remediation

| ID | Vulnerability and impact | Secure measure applied |
|---|---|---|
| S1 | SQL queries were built through string interpolation. Specially crafted input could change the meaning of a query and allow unauthorized data access. | Every database statement in `secure_account_manager.py` uses SQLite parameter placeholders (`?`) with a separate parameter tuple. |
| S2 | Passwords were stored as plaintext. A database disclosure would expose every password directly. | Passwords are derived with PBKDF2-HMAC-SHA256 using 200,000 iterations and a unique cryptographically random 16-byte salt. Only the hash and salt are stored. |
| S3 | Password input could be displayed in the terminal. | The CLI uses `getpass.getpass` so password text is not echoed. |
| S4 | Weak or malformed input could create poor accounts or unexpected behavior. | Username allow-list validation and password length and complexity rules reject invalid registration input. |
| S5 | Database exceptions were printed to users. This could reveal internal implementation details. | Registration handles duplicate-user integrity errors safely, while authentication returns a generic boolean result. The CLI shows generic login failure messages. |
| S6 | User enumeration may be assisted by different processing paths for missing accounts. | Authentication performs a PBKDF2 operation for missing users and uses `hmac.compare_digest` for hash comparison. |

## Secure Code Examples

Parameterized query:

```python
connection.execute(
    "SELECT password_hash, salt FROM users WHERE username = ?", (username,)
)
```

Password derivation:

```python
salt = secrets.token_bytes(16)
password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
```

## Validation

The automated test suite verifies successful registration and authentication, incorrect password rejection, duplicate user handling, invalid username and weak password rejection, absence of plaintext passwords in the database, safe handling of an SQL-injection-style username, and unknown user behavior.

Run tests with:

```bash
python -m unittest test_secure_account_manager.py
```

## Limitations and Further Measures

This is a local educational CLI application. A production web application would also require TLS, rate limiting, account lockout policies, secure secret management, audit logging with privacy controls, dependency scanning, database access controls, and an incident response process.
