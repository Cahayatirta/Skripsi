"""
tests/test_auth.py
------------------
Automated test suite for the authentication and OTP email verification system:
1. User registration validation & database persistence.
2. Salted password hashing (PBKDF2-HMAC-SHA256) & verification.
3. OTP code generation, 6-digit format & 5-minute expiration checks.
4. Pre-seeded default admin account (admin@gmail.com / admin) validation.
5. Email verification & user authentication lifecycle.
6. SMTP dispatch with development fallback mode.
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_utils import (
    init_db,
    hash_password,
    verify_password,
    generate_otp,
    is_otp_valid,
    send_otp_email,
    register_user,
    mark_user_verified,
    authenticate_user,
    get_user_record,
    OTP_EXPIRY_SECONDS,
)


class TestPasswordHashing(unittest.TestCase):
    """Test cryptographic password hashing and verification."""

    def test_password_hash_and_verify_roundtrip(self):
        pwd = "MySecretPassword123!"
        hashed = hash_password(pwd)
        self.assertIn("$", hashed)
        self.assertTrue(verify_password(hashed, pwd))
        self.assertFalse(verify_password(hashed, "WrongPassword!"))

    def test_unique_salts_for_identical_passwords(self):
        pwd = "identical_password"
        hash1 = hash_password(pwd)
        hash2 = hash_password(pwd)
        self.assertNotEqual(hash1, hash2)
        self.assertTrue(verify_password(hash1, pwd))
        self.assertTrue(verify_password(hash2, pwd))


class TestOTPLogic(unittest.TestCase):
    """Test OTP code generation and validation rules."""

    def test_otp_format_and_expiry(self):
        otp, expires_at = generate_otp()
        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())
        now = time.time()
        self.assertGreater(expires_at, now)
        self.assertLessEqual(expires_at - now, OTP_EXPIRY_SECONDS + 1)

    def test_otp_validation_matching(self):
        otp, expires_at = generate_otp()
        valid, msg = is_otp_valid(otp, otp, expires_at)
        self.assertTrue(valid)
        self.assertIn("valid", msg.lower())

    def test_otp_validation_mismatch(self):
        otp, expires_at = generate_otp()
        valid, msg = is_otp_valid("000000", otp, expires_at)
        self.assertFalse(valid)
        self.assertIn("salah", msg.lower())

    def test_otp_validation_expired(self):
        otp = "123456"
        expired_time = time.time() - 10  # 10 seconds in the past
        valid, msg = is_otp_valid(otp, otp, expired_time)
        self.assertFalse(valid)
        self.assertIn("kadaluarsa", msg.lower())

    def test_smtp_fallback_mode_when_unconfigured(self):
        """When SMTP env vars are absent, fallback mode provides simulated OTP without error."""
        otp, _ = generate_otp()
        # Ensure SMTP env vars are empty
        old_email = os.environ.pop("SMTP_EMAIL", None)
        old_pass = os.environ.pop("SMTP_APP_PASSWORD", None)
        try:
            success, msg = send_otp_email("testuser@gmail.com", otp)
            self.assertTrue(success)
            self.assertIn("[DEV MODE]", msg)
            self.assertIn(otp, msg)
        finally:
            if old_email:
                os.environ["SMTP_EMAIL"] = old_email
            if old_pass:
                os.environ["SMTP_APP_PASSWORD"] = old_pass


class TestUserRegistrationAndAuth(unittest.TestCase):
    """Test database persistence and user authentication flow."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_users.db")
        init_db(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_admin_pre_seeded(self):
        """Admin account must be pre-seeded and verified on initialization."""
        rec = get_user_record("admin@gmail.com", self.db_path)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["email"], "admin@gmail.com")
        self.assertEqual(rec["is_verified"], 1)

        # Authenticate admin with default credentials
        ok, msg, is_admin = authenticate_user("admin@gmail.com", "admin", self.db_path)
        self.assertTrue(ok)
        self.assertTrue(is_admin)

    def test_register_invalid_email_format(self):
        """Non-Gmail addresses must be rejected."""
        ok, msg = register_user("user@yahoo.com", "secret", self.db_path)
        self.assertFalse(ok)
        self.assertIn("Gmail", msg)

        ok, msg = register_user("not_an_email", "secret", self.db_path)
        self.assertFalse(ok)

    def test_registration_verification_login_lifecycle(self):
        """End-to-end user registration -> verification -> successful login."""
        email = "cahayatirta11@gmail.com"
        pwd = "SafePassword2026"

        # 1. Register
        ok, msg = register_user(email, pwd, self.db_path)
        self.assertTrue(ok)

        # 2. Try logging in before verification (must fail)
        ok_login, msg_login, is_admin = authenticate_user(email, pwd, self.db_path)
        self.assertFalse(ok_login)
        self.assertIn("belum diverifikasi", msg_login)

        # 3. Mark verified (simulating correct OTP)
        mark_user_verified(email, self.db_path)

        # 4. Login after verification (must succeed)
        ok_login, msg_login, is_admin = authenticate_user(email, pwd, self.db_path)
        self.assertTrue(ok_login)
        self.assertFalse(is_admin)

        # 5. Wrong password fails
        ok_wrong, msg_wrong, _ = authenticate_user(email, "WrongPassword!", self.db_path)
        self.assertFalse(ok_wrong)
        self.assertIn("tidak sesuai", msg_wrong)

    def test_duplicate_registration_prevented_when_verified(self):
        """Verified users cannot re-register the same email."""
        email = "verified@gmail.com"
        register_user(email, "password123", self.db_path)
        mark_user_verified(email, self.db_path)

        ok, msg = register_user(email, "new_password", self.db_path)
        self.assertFalse(ok)
        self.assertIn("sudah terdaftar dan terverifikasi", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)

