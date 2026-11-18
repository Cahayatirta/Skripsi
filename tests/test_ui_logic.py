"""
tests/test_ui_logic.py
----------------------
Unit and integration tests for Streamlit UI logic:
1. Login validation (Gmail regex/suffix, Admin credential checks).
2. Status dropdown filtering (only 3 allowed choices; duplicate 'Asli' removed).
3. Absolute Stego-Key isolation (never exposed or requested in UI inputs).
4. RBAC Admin extraction privilege checks.
5. Streamlit AppTest session state workflow.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import (
    UI_STATUS_CHOICES,
    ADMIN_EMAIL,
)
from auth_utils import (
    authenticate_user,
    register_user,
    mark_user_verified,
    init_db,
)
from embedder import VALID_STATUSES
from env_utils import load_env, get_admin_key, get_stego_key
from rbac_utils import Role, determine_role, is_full_access


class TestUILoginLogic(unittest.TestCase):
    """Test login gatekeeper validation logic."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_ui_users.db")
        init_db(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_valid_user_gmail(self):
        """Standard valid Gmail addresses must pass registration and authentication."""
        reg_ok, msg = register_user("cahayatirta11@gmail.com", "Password123!", self.db_path)
        self.assertTrue(reg_ok)
        mark_user_verified("cahayatirta11@gmail.com", self.db_path)

        ok, msg, is_admin = authenticate_user("cahayatirta11@gmail.com", "Password123!", self.db_path)
        self.assertTrue(ok)
        self.assertFalse(is_admin)

    def test_invalid_email_rejected(self):
        """Non-Gmail or malformed emails must be rejected during registration."""
        for em in ["user@yahoo.com", "user@outlook.com", "@gmail.com", "plainaddress"]:
            ok, msg = register_user(em, "Password123!", self.db_path)
            self.assertFalse(ok, f"Expected {em} to fail registration")
            self.assertIn("gmail", msg.lower())

    def test_admin_login_success(self):
        """Admin email with correct password 'admin' must succeed and set is_admin=True."""
        ok, msg, is_admin = authenticate_user(ADMIN_EMAIL, "admin", self.db_path)
        self.assertTrue(ok)
        self.assertTrue(is_admin)

    def test_admin_login_wrong_password(self):
        """Admin email with incorrect password must fail validation."""
        ok, msg, is_admin = authenticate_user(ADMIN_EMAIL, "wrongpass", self.db_path)
        self.assertFalse(ok)
        self.assertIn("tidak sesuai", msg.lower())
        self.assertFalse(is_admin)


class TestUIControlsAndIsolation(unittest.TestCase):
    """Test UI control simplification and Stego-Key isolation."""

    def test_status_dropdown_choices(self):
        """Status selection must contain ONLY 3 choices and no 'Asli'."""
        expected = ["AI Generated", "Edited", "Original"]
        self.assertEqual(sorted(UI_STATUS_CHOICES), sorted(expected))
        self.assertNotIn("Asli", UI_STATUS_CHOICES)
        self.assertEqual(len(UI_STATUS_CHOICES), 3)

        # All UI choices must be recognized by backend VALID_STATUSES
        for choice in UI_STATUS_CHOICES:
            self.assertIn(choice, VALID_STATUSES)

    def test_stego_key_absolute_isolation(self):
        """
        Verify that STEGO_SECRET_KEY is never requested via st.text_input,
        prompted to the user, or displayed in the UI frontend.
        """
        app_file_path = Path(__file__).parent.parent / "app.py"
        with open(app_file_path, "r", encoding="utf-8") as f:
            code = f.read()

        # Ensure no UI input exists for stego key
        self.assertNotIn('st.text_input("🔑 Stego-Key', code)
        self.assertNotIn('st.text_input("Stego-Key', code)
        self.assertNotIn("input_stego_key", code)
        self.assertNotIn("type=\"password\", value=default_env_stego_key", code)


class TestAdminExtractionPrivilege(unittest.TestCase):
    """Test RBAC extraction privileges for Admin vs User."""

    def setUp(self):
        load_env()
        self.env_admin_key = get_admin_key()

    def test_admin_with_correct_key_gets_full_access(self):
        """Admin user providing matching ADMIN_KEY gets Role.ADMIN (Full Access)."""
        creator = "creator@gmail.com"
        role = determine_role(
            user_email="admin@gmail.com",
            admin_key_input=self.env_admin_key,
            creator_email=creator,
            env_admin_key=self.env_admin_key,
        )
        self.assertEqual(role, Role.ADMIN)
        self.assertTrue(is_full_access(role))

    def test_admin_without_correct_key_gets_guest_access(self):
        """Admin user with empty or incorrect secret key falls back to Role.GUEST."""
        creator = "creator@gmail.com"
        role_wrong = determine_role(
            user_email="admin@gmail.com",
            admin_key_input="WrongAdminKey!",
            creator_email=creator,
            env_admin_key=self.env_admin_key,
        )
        self.assertEqual(role_wrong, Role.GUEST)
        self.assertFalse(is_full_access(role_wrong))

        role_empty = determine_role(
            user_email="admin@gmail.com",
            admin_key_input="",
            creator_email=creator,
            env_admin_key=self.env_admin_key,
        )
        self.assertEqual(role_empty, Role.GUEST)
        self.assertFalse(is_full_access(role_empty))

    def test_creator_gets_full_access_without_admin_key(self):
        """Original creator gets Role.CREATOR (Full Access) by email match alone."""
        creator = "cahayatirta11@gmail.com"
        role = determine_role(
            user_email=creator,
            admin_key_input="",
            creator_email=creator,
            env_admin_key=self.env_admin_key,
        )
        self.assertEqual(role, Role.CREATOR)
        self.assertTrue(is_full_access(role))

    def test_other_user_gets_restricted_access(self):
        """A different user without admin key gets Role.GUEST (Restricted Access)."""
        creator = "cahayatirta11@gmail.com"
        role = determine_role(
            user_email="guest@gmail.com",
            admin_key_input="",
            creator_email=creator,
            env_admin_key=self.env_admin_key,
        )
        self.assertEqual(role, Role.GUEST)
        self.assertFalse(is_full_access(role))


class TestStreamlitAppTest(unittest.TestCase):
    """Test Streamlit component lifecycle using AppTest."""

    def test_app_unauthenticated_state(self):
        """Unauthenticated session shows login/registration portal and halts before main 3 tabs."""
        from streamlit.testing.v1 import AppTest

        at = AppTest.from_file("app.py")
        at.run()
        self.assertFalse(at.exception)
        # Login and registration inputs should be present
        self.assertTrue(len(at.text_input) >= 1)
        # Main application 3 tabs should NOT be rendered yet (only the 2 auth portal sub-tabs)
        self.assertNotEqual(len(at.tabs), 3)

    def test_app_authenticated_user_state(self):
        """Authenticated session renders all 3 tabs and displays user profile in sidebar."""
        from streamlit.testing.v1 import AppTest

        at = AppTest.from_file("app.py")
        at.session_state["logged_in"] = True
        at.session_state["user_email"] = "cahayatirta11@gmail.com"
        at.session_state["is_admin"] = False
        at.run()

        self.assertFalse(at.exception)
        # 3 main tabs should now be present
        self.assertEqual(len(at.tabs), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
