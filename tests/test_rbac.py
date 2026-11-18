"""
tests/test_rbac.py
------------------
Automated tests for:
  1. .env auto-key generation (STEGO_SECRET_KEY + ADMIN_KEY).
  2. Key loading precedence (override > env).
  3. Creator access: full decrypted private metadata.
  4. Admin access: full decrypted private metadata via ADMIN_KEY.
  5. Guest access: metadata masked / ACCESS DENIED.
  6. CLI RBAC integration: embed + extract with each role.

Run with:
  python -m pytest tests/test_rbac.py -v
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import numpy as np
from PIL import Image

# Make project root importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from embedder import embed
from extractor import extract_and_verify, _decode_payload
from env_utils import load_env, get_stego_key, get_admin_key
from rbac_utils import Role, determine_role, is_full_access, role_label

_STEGO_KEY   = "UnitTestStegoKey!"
_CREATOR     = "cahayatirta11@gmail.com"
_GUEST       = "guest@example.com"
_ADMIN_KEY   = "SuperSecretAdminKey2026"   # synthetic; injected via env fixture


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_image(width: int, height: int, tmp_dir: str, name: str = "cover.png") -> str:
    path = os.path.join(tmp_dir, name)
    arr = np.random.randint(80, 180, (height, width, 3), dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path, format="PNG")
    return path


def _capture_extract(image_path, stego_key, user_email=None, admin_key_input=None, env_admin_key=None):
    """Run extract_and_verify and capture stdout to a string."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        extract_and_verify(
            image_path=image_path,
            stego_key=stego_key,
            user_email=user_email,
            admin_key_input=admin_key_input,
            env_admin_key=env_admin_key or "",
            show_stats=False,
        )
    return buf.getvalue()


# ===========================================================================
# 1. .env Key Loading & Auto-Generation
# ===========================================================================

class TestEnvUtils(unittest.TestCase):

    def test_auto_generates_stego_key_when_missing(self):
        """If .env has no STEGO_SECRET_KEY, load_env must generate and save one."""
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            # Ensure env var not already set from a previous test
            os.environ.pop("STEGO_SECRET_KEY", None)
            os.environ.pop("ADMIN_KEY", None)

            load_env(env_path=env_path)

            # Key must now be in os.environ
            key = os.environ.get("STEGO_SECRET_KEY", "")
            self.assertTrue(len(key) > 0, "STEGO_SECRET_KEY must be auto-generated")

            # Key must be persisted to .env file
            self.assertTrue(os.path.exists(env_path), ".env file must be created")
            content = Path(env_path).read_text()
            self.assertIn("STEGO_SECRET_KEY", content)

    def test_auto_generates_admin_key_when_missing(self):
        """If .env has no ADMIN_KEY, load_env must generate and save one."""
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            os.environ.pop("STEGO_SECRET_KEY", None)
            os.environ.pop("ADMIN_KEY", None)

            load_env(env_path=env_path)

            admin = os.environ.get("ADMIN_KEY", "")
            self.assertTrue(len(admin) > 0, "ADMIN_KEY must be auto-generated")
            content = Path(env_path).read_text()
            self.assertIn("ADMIN_KEY", content)

    def test_existing_env_key_is_not_overwritten(self):
        """If STEGO_SECRET_KEY already exists in .env, it must not be changed."""
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            fixed_key = "fixed_key_that_must_survive"
            Path(env_path).write_text(f"STEGO_SECRET_KEY={fixed_key}\nADMIN_KEY=someadmin\n")

            os.environ.pop("STEGO_SECRET_KEY", None)
            os.environ.pop("ADMIN_KEY", None)

            load_env(env_path=env_path)

            self.assertEqual(os.environ["STEGO_SECRET_KEY"], fixed_key)

    def test_get_stego_key_override_takes_priority(self):
        """--key override must take priority over env value."""
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            os.environ.pop("STEGO_SECRET_KEY", None)
            os.environ.pop("ADMIN_KEY", None)

            key = get_stego_key(override="MyExplicitKey", env_path=env_path)
            self.assertEqual(key, "MyExplicitKey")

    def test_get_stego_key_reads_from_env(self):
        """Without override, get_stego_key must return the env value."""
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            Path(env_path).write_text("STEGO_SECRET_KEY=env_value_123\nADMIN_KEY=admin\n")
            os.environ.pop("STEGO_SECRET_KEY", None)
            os.environ.pop("ADMIN_KEY", None)

            key = get_stego_key(env_path=env_path)
            self.assertEqual(key, "env_value_123")

    def test_generated_keys_are_unique(self):
        """Two independent load_env calls must produce distinct keys."""
        keys = set()
        for _ in range(3):
            with tempfile.TemporaryDirectory() as tmp:
                env_path = os.path.join(tmp, ".env")
                os.environ.pop("STEGO_SECRET_KEY", None)
                os.environ.pop("ADMIN_KEY", None)
                load_env(env_path=env_path)
                keys.add(os.environ["STEGO_SECRET_KEY"])
        self.assertEqual(len(keys), 3, "Each auto-generated key must be unique")


# ===========================================================================
# 2. RBAC Role Determination Logic
# ===========================================================================

class TestRbacRoles(unittest.TestCase):

    def test_admin_role_with_matching_key(self):
        role = determine_role(
            user_email=_GUEST,
            admin_key_input=_ADMIN_KEY,
            creator_email=_CREATOR,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertEqual(role, Role.ADMIN)
        self.assertTrue(is_full_access(role))

    def test_admin_role_not_granted_with_wrong_key(self):
        role = determine_role(
            user_email="anyuser@gmail.com",
            admin_key_input="WrongAdminKey",
            creator_email=_CREATOR,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertNotEqual(role, Role.ADMIN)

    def test_creator_role_with_matching_email(self):
        role = determine_role(
            user_email=_CREATOR,
            admin_key_input="",
            creator_email=_CREATOR,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertEqual(role, Role.CREATOR)
        self.assertTrue(is_full_access(role))

    def test_creator_role_case_insensitive(self):
        """Email comparison must be case-insensitive."""
        role = determine_role(
            user_email=_CREATOR.upper(),
            admin_key_input="",
            creator_email=_CREATOR,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertEqual(role, Role.CREATOR)

    def test_guest_role_when_neither_matches(self):
        role = determine_role(
            user_email=_GUEST,
            admin_key_input="",
            creator_email=_CREATOR,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertEqual(role, Role.GUEST)
        self.assertFalse(is_full_access(role))

    def test_admin_takes_precedence_over_creator(self):
        """If user is also the creator AND provides the admin key, Admin wins."""
        role = determine_role(
            user_email=_CREATOR,
            admin_key_input=_ADMIN_KEY,
            creator_email=_CREATOR,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertEqual(role, Role.ADMIN)

    def test_empty_admin_key_not_granted(self):
        """Empty admin_key_input must never grant Admin role."""
        role = determine_role(
            user_email=_GUEST,
            admin_key_input="",
            creator_email=_CREATOR,
            env_admin_key="",  # both empty
        )
        self.assertEqual(role, Role.GUEST)

    def test_role_label_strings(self):
        self.assertIn("Full Access", role_label(Role.ADMIN))
        self.assertIn("Full Access", role_label(Role.CREATOR))
        self.assertIn("Restricted", role_label(Role.GUEST))


# ===========================================================================
# 3. RBAC-Gated Extraction: Creator Access
# ===========================================================================

class TestRbacExtraction(unittest.TestCase):

    def setUp(self):
        """Embed a test stego image shared across all role tests."""
        self._tmp = tempfile.mkdtemp()
        cover = _make_image(512, 512, self._tmp, "cover.png")
        self._stego = os.path.join(self._tmp, "stego.png")
        img = Image.open(cover)
        w, h = img.size
        img.close()
        embed(cover, self._stego, _CREATOR, "AI Generated", _STEGO_KEY, w, h)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    # ------------------------------------------------------------------
    # Creator
    # ------------------------------------------------------------------

    def test_creator_receives_full_report(self):
        """Creator email matching initial embed must receive full private data."""
        output = _capture_extract(
            self._stego, _STEGO_KEY,
            user_email=_CREATOR,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertIn("VALID", output)
        self.assertIn("Creator (Full Access)", output)
        self.assertIn("CREATOR CREDENTIAL", output)
        self.assertIn(_CREATOR, output)
        self.assertIn("CREDENTIAL HISTORY", output)
        self.assertIn("AI Generated", output)

    def test_creator_full_report_contains_history(self):
        """Full report must include at least one history entry."""
        output = _capture_extract(
            self._stego, _STEGO_KEY,
            user_email=_CREATOR,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertIn("1.", output)   # at least one history entry

    # ------------------------------------------------------------------
    # Admin
    # ------------------------------------------------------------------

    def test_admin_receives_full_report(self):
        """Valid ADMIN_KEY must grant full access regardless of email."""
        output = _capture_extract(
            self._stego, _STEGO_KEY,
            user_email=_GUEST,            # not the creator
            admin_key_input=_ADMIN_KEY,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertIn("VALID", output)
        self.assertIn("Admin (Full Access)", output)
        self.assertIn("CREATOR CREDENTIAL", output)
        self.assertIn("CREDENTIAL HISTORY", output)

    def test_admin_with_wrong_key_gets_restricted(self):
        """Wrong ADMIN_KEY + non-creator email must produce Guest/restricted report."""
        output = _capture_extract(
            self._stego, _STEGO_KEY,
            user_email=_GUEST,
            admin_key_input="WrongAdminKey!",
            env_admin_key=_ADMIN_KEY,
        )
        self.assertIn("ACCESS DENIED", output)
        self.assertNotIn("CREATOR CREDENTIAL", output)
        self.assertNotIn("CREDENTIAL HISTORY", output)

    # ------------------------------------------------------------------
    # Guest
    # ------------------------------------------------------------------

    def test_guest_receives_restricted_report(self):
        """Guest must see only public status and ACCESS DENIED message."""
        output = _capture_extract(
            self._stego, _STEGO_KEY,
            user_email=_GUEST,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertIn("VALID", output)
        self.assertIn("Guest (Restricted)", output)
        self.assertIn("ACCESS DENIED", output)
        # Private details must NOT appear
        self.assertNotIn("CREATOR CREDENTIAL", output)
        self.assertNotIn("CREDENTIAL HISTORY", output)
        self.assertNotIn(_CREATOR, output)

    def test_guest_still_sees_public_status(self):
        """Guest restricted report must still show the image status."""
        output = _capture_extract(
            self._stego, _STEGO_KEY,
            user_email=_GUEST,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertIn("AI Generated", output)

    def test_no_email_provided_gets_guest_role(self):
        """Omitting --email entirely must produce Guest/restricted output."""
        output = _capture_extract(
            self._stego, _STEGO_KEY,
            user_email=None,
            env_admin_key=_ADMIN_KEY,
        )
        self.assertIn("ACCESS DENIED", output)


# ===========================================================================
# 4. CLI RBAC Integration
# ===========================================================================

class TestCLIRbac(unittest.TestCase):

    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _run(self, *args, check=True):
        result = subprocess.run(
            [sys.executable, "cli.py", *args],
            capture_output=True, text=True, cwd=self._ROOT,
        )
        if check and result.returncode != 0:
            self.fail(
                f"CLI failed (exit {result.returncode}):\n"
                f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
            )
        return result

    def test_cli_creator_full_access(self):
        """CLI extract as creator must print full access report."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            self._run("embed", cover, stego, _CREATOR, "Original", "--key", _STEGO_KEY)
            result = self._run(
                "extract", stego,
                "--email", _CREATOR,
                "--key", _STEGO_KEY,
            )
            self.assertIn("Creator (Full Access)", result.stdout)
            self.assertIn("CREATOR CREDENTIAL", result.stdout)

    def test_cli_admin_full_access(self):
        """CLI extract with valid --admin-key must print Admin full access report."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            self._run("embed", cover, stego, _CREATOR, "Original", "--key", _STEGO_KEY)

            # Temporarily set ADMIN_KEY in environment so CLI can compare
            env = os.environ.copy()
            env["ADMIN_KEY"] = _ADMIN_KEY
            result = subprocess.run(
                [sys.executable, "cli.py", "extract", stego,
                 "--email", _GUEST,
                 "--admin-key", _ADMIN_KEY,
                 "--key", _STEGO_KEY],
                capture_output=True, text=True, cwd=self._ROOT, env=env,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Admin (Full Access)", result.stdout)

    def test_cli_guest_restricted(self):
        """CLI extract as guest must print restricted / ACCESS DENIED report."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            self._run("embed", cover, stego, _CREATOR, "Edited", "--key", _STEGO_KEY)
            result = self._run(
                "extract", stego,
                "--email", _GUEST,
                "--key", _STEGO_KEY,
            )
            self.assertIn("ACCESS DENIED", result.stdout)
            self.assertNotIn("CREATOR CREDENTIAL", result.stdout)


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
