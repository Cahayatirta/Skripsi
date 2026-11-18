"""
rbac_utils.py
-------------
Role-Based Access Control (RBAC) for steganography metadata visibility.

Role Hierarchy
--------------
  ADMIN   -- Holds valid ADMIN_KEY from .env. Full access.
  CREATOR -- Gmail matches creator_email in private metadata. Full access.
  GUEST   -- Any other user. Public metadata + integrity status only.

Usage
-----
    role = determine_role(
        user_email="someone@gmail.com",
        admin_key_input="",
        creator_email="cahayatirta11@gmail.com",
        env_admin_key=get_admin_key(),
    )
    if is_full_access(role):
        # render full report
    else:
        # render restricted report
"""

from enum import Enum


# ---------------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------------

class Role(Enum):
    ADMIN   = "Admin"
    CREATOR = "Creator"
    GUEST   = "Guest"


# ---------------------------------------------------------------------------
# Role determination
# ---------------------------------------------------------------------------

def determine_role(
    user_email: str,
    admin_key_input: str,
    creator_email: str,
    env_admin_key: str,
) -> Role:
    """
    Evaluate the requester's role for metadata access.

    Precedence: Admin > Creator > Guest.

    Args:
        user_email:      Gmail supplied via --email (may be empty string / None).
        admin_key_input: Key supplied via --admin-key (may be empty string / None).
        creator_email:   creator_email extracted from the embedded private metadata.
        env_admin_key:   ADMIN_KEY value loaded from .env.

    Returns:
        Role enum member.
    """
    # Normalize inputs to avoid None comparison issues
    admin_input = (admin_key_input or "").strip()
    env_admin   = (env_admin_key or "").strip()
    u_email     = (user_email or "").strip().lower()
    c_email     = (creator_email or "").strip().lower()

    # 1. Admin: non-empty key that matches env ADMIN_KEY
    if admin_input and env_admin and admin_input == env_admin:
        return Role.ADMIN

    # 2. Creator: Gmail matches (case-insensitive)
    if u_email and c_email and u_email == c_email:
        return Role.CREATOR

    # 3. Fallback: Guest / restricted
    return Role.GUEST


# ---------------------------------------------------------------------------
# Access-level helpers
# ---------------------------------------------------------------------------

def is_full_access(role: Role) -> bool:
    """Return True if the role grants full private metadata access."""
    return role in (Role.ADMIN, Role.CREATOR)


def role_label(role: Role) -> str:
    """Return a human-readable access-level label for terminal output."""
    labels = {
        Role.ADMIN:   "Admin (Full Access)",
        Role.CREATOR: "Creator (Full Access)",
        Role.GUEST:   "Guest (Restricted)",
    }
    return labels.get(role, "Unknown")
