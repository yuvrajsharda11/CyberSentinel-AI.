"""Authentication bootstrap behavior for development and production modes."""
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from services.auth import init_db


class AuthBootstrapTests(unittest.TestCase):
    def _temp_db(self):
        handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        handle.close()
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        return handle.name

    def test_production_ignores_demo_flag_and_bootstraps_named_admin(self):
        db = self._temp_db()
        env = {"CYBERSENTINEL_ENV": "production", "CYBERSENTINEL_DEMO_ADMIN": "1",
               "CYBERSENTINEL_ADMIN_USERNAME": "securityadmin",
               "CYBERSENTINEL_ADMIN_PASSWORD": "Strong-Unique-Admin-123!"}
        with patch.dict(os.environ, env, clear=True):
            init_db(db)
        con = sqlite3.connect(db)
        users = {row[0] for row in con.execute("SELECT username FROM users")}
        con.close()
        self.assertEqual(users, {"securityadmin"})

    def test_production_rejects_weak_bootstrap_password(self):
        db = self._temp_db()
        env = {"CYBERSENTINEL_ENV": "production", "CYBERSENTINEL_ADMIN_USERNAME": "admin",
               "CYBERSENTINEL_ADMIN_PASSWORD": "weak123"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "at least 14 characters"):
                init_db(db)

    def test_development_demo_account_still_bootstraps(self):
        db = self._temp_db()
        with patch.dict(os.environ, {"CYBERSENTINEL_ENV": "development"}, clear=True):
            init_db(db)
        con = sqlite3.connect(db)
        users = {row[0] for row in con.execute("SELECT username FROM users")}
        con.close()
        self.assertIn("admin", users)

    def test_production_invalidates_existing_known_demo_password(self):
        db = self._temp_db()
        with patch.dict(os.environ, {"CYBERSENTINEL_ENV": "development"}, clear=True):
            init_db(db)
        env = {"CYBERSENTINEL_ENV": "production", "CYBERSENTINEL_ADMIN_USERNAME": "securityadmin",
               "CYBERSENTINEL_ADMIN_PASSWORD": "Strong-Unique-Admin-123!"}
        with patch.dict(os.environ, env, clear=True):
            init_db(db)
        con = sqlite3.connect(db)
        admin_hash = con.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()[0]
        con.close()
        import bcrypt
        self.assertFalse(bcrypt.checkpw(b"admin123", admin_hash.encode()))


class MetricTests(unittest.TestCase):
    def test_false_positive_and_false_negative_rates(self):
        from ml.train_url_model import _metrics
        result = _metrics([0, 0, 1, 1], [0, 1, 0, 1], [0.1, 0.8, 0.3, 0.9])
        self.assertEqual(result["false_positive_rate"], 0.5)
        self.assertEqual(result["false_negative_rate"], 0.5)
        self.assertEqual(result["confusion_matrix"]["false_positive"], 1)


if __name__ == "__main__":
    unittest.main()
