# Week 5 Security Enhancements Project

## Files

- `insecure_account_manager.py`: educational comparison file containing insecure patterns.
- `secure_account_manager.py`: hardened SQLite account manager.
- `test_secure_account_manager.py`: functional and security-focused automated tests.
- `SECURITY_AUDIT_REPORT.md`: risks, fixes, code examples, and validation details.

## Run Tests

```bash
python -m unittest test_secure_account_manager.py
```

## Run the Local CLI

```bash
python secure_account_manager.py
```

The application uses Python standard-library modules only. It creates a local `accounts.db` database when run.
