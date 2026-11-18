"""
extractor.py
------------
Module 2: Secure Metadata Extraction, Integrity Verification & RBAC output.

Workflow:
  1. Extract raw bitstream from DCT mid-frequency coefficients.
  2. Parse binary payload structure.
  3. Verify SHA-256 integrity hash — abort if mismatch.
  4. Decrypt AES-128 ciphertext.
  5. Determine RBAC role (Admin / Creator / Guest).
  6. Render role-appropriate formatted verification report.

RBAC Output Behaviour:
  ADMIN / CREATOR  -- Full report: creator credential + complete history.
  GUEST            -- Public status + integrity indicator only; private data masked.
"""

import json
from datetime import datetime, timezone

from crypto_utils import aes_decrypt, verify_sha256
from dct_utils import extract_payload, compute_payload_bits
from capacity_utils import print_capacity_stats, print_bit_stats
from rbac_utils import Role, determine_role, is_full_access, role_label
from PIL import Image

BLOCK: int = 8


# ---------------------------------------------------------------------------
# Internal decode helpers
# ---------------------------------------------------------------------------

def _decode_payload(image_path: str, stego_key: str):
    """
    Extract + decrypt private metadata without printing anything.

    Returns:
        (creator_credential dict, credential_history list)

    Raises:
        ValueError: on SHA-256 mismatch, decryption failure, or parse error.
    """
    _, _, creator_credential, credential_history = _decode_all(image_path, stego_key)
    return creator_credential, credential_history


def _decode_all(image_path: str, stego_key: str):
    """
    Extract + decrypt the full payload without printing.

    Returns:
        (pub_data dict, integrity_ok bool, creator_credential dict, credential_history list)

    Raises:
        ValueError: on SHA-256 mismatch, decryption failure, or parse error.
    """
    header_bytes, pub_bytes, cipher_bytes, sha256_bytes = extract_payload(image_path)

    # --- Integrity verification ---
    if not verify_sha256(cipher_bytes, sha256_bytes):
        raise ValueError("INTEGRITY ERROR: Metadata has been altered or corrupted.")

    # --- Parse header for AES IV ---
    header_dict = json.loads(header_bytes.decode("utf-8"))
    iv = bytes.fromhex(header_dict["iv"])

    # --- Decrypt private metadata ---
    private_json = aes_decrypt(cipher_bytes, iv, stego_key)
    private_data = json.loads(private_json)

    # --- Parse public metadata ---
    try:
        pub_data = json.loads(pub_bytes.decode("utf-8"))
    except json.JSONDecodeError:
        pub_data = {}

    creator_credential = private_data.get("creator_credential", {})
    credential_history = private_data.get("credential_history", [])

    return pub_data, True, creator_credential, credential_history


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _fmt_timestamp(ts_raw: str) -> str:
    """Parse ISO UTC timestamp into readable local format."""
    try:
        dt = datetime.strptime(ts_raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts_raw


def _render_full_report(
    integrity_label: str,
    role: Role,
    pub_data: dict,
    creator_credential: dict,
    credential_history: list,
) -> None:
    """Render the full access verification report (Admin / Creator)."""
    sep = "=" * 54
    print()
    print(sep)
    print("  SECURE METADATA VERIFICATION REPORT")
    print(sep)
    print(f"  [STATUS INTEGRITAS] : {integrity_label}")
    print(f"  [ROLE]              : {role_label(role)}")
    print(f"  [STATUS TERAKHIR]   : {pub_data.get('current_status', 'N/A')}")
    print(f"  [LAST MODIFIED BY]  : {pub_data.get('last_modified_by', 'N/A')}")
    print()
    print("  [CREATOR CREDENTIAL]:")
    print(f"    Creator Email : {creator_credential.get('creator_email', 'N/A')}")
    print(f"    Created At    : {creator_credential.get('created_at', 'N/A')}")
    print()
    print("  [CREDENTIAL HISTORY]:")
    for idx, entry in enumerate(credential_history, start=1):
        ts_fmt = _fmt_timestamp(entry.get("timestamp", ""))
        print(
            f"    {idx}. {entry.get('action', '')} oleh "
            f"{entry.get('user_email', '')} ({ts_fmt})"
        )
    print(sep)


def _render_restricted_report(
    integrity_label: str,
    pub_data: dict,
) -> None:
    """Render the restricted access report (Guest)."""
    sep = "=" * 54
    print()
    print(sep)
    print("  SECURE METADATA VERIFICATION REPORT")
    print(sep)
    print(f"  [STATUS INTEGRITAS] : {integrity_label}")
    print(f"  [ROLE]              : Guest (Restricted)")
    print(f"  [STATUS TERAKHIR]   : {pub_data.get('current_status', 'N/A')}")
    print()
    print("  ACCESS DENIED: Private metadata is restricted")
    print("  to Image Creator or System Admin.")
    print(sep)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_and_verify(
    image_path: str,
    stego_key: str,
    user_email: str = None,
    admin_key_input: str = None,
    env_admin_key: str = None,
    show_stats: bool = True,
) -> None:
    """
    Full extraction + integrity verification + RBAC-aware report pipeline.

    Args:
        image_path:      Path to the stego image.
        stego_key:       AES key used during embedding (from env or --key).
        user_email:      Requester's Gmail for Creator role check (--email).
        admin_key_input: Optional admin key for Admin role check (--admin-key).
        env_admin_key:   ADMIN_KEY from .env (injected by cli.py).
        show_stats:      If True, print DCT capacity statistics first.
    """
    img = Image.open(image_path)
    w, h = img.size
    img.close()

    # --- Extract raw payload components ---
    try:
        header_bytes, pub_bytes, cipher_bytes, sha256_bytes = extract_payload(image_path)
    except ValueError as exc:
        if show_stats:
            print_capacity_stats(w, h, required_bits=0, label="Extraction")
        print(f"\n[ERROR] {exc}")
        return

    # Calculate exact number of bits extracted
    extracted_payload_bits = compute_payload_bits(header_bytes, pub_bytes, cipher_bytes, sha256_bytes)

    if show_stats:
        print_capacity_stats(w, h, required_bits=extracted_payload_bits, label="Extraction")

    # --- SHA-256 integrity gate ---
    integrity_ok = verify_sha256(cipher_bytes, sha256_bytes)
    integrity_label = "VALID (SHA-256 Match)" if integrity_ok else "INVALID (SHA-256 Mismatch)"

    if not integrity_ok:
        sep = "=" * 54
        print(f"\n{sep}")
        print("  SECURE METADATA VERIFICATION REPORT")
        print(sep)
        print(f"  [STATUS INTEGRITAS] : {integrity_label}")
        print("  INTEGRITY ERROR: Metadata has been altered or corrupted.")
        print(sep)
        return

    # --- Parse public metadata (always available, even for guests) ---
    try:
        pub_data = json.loads(pub_bytes.decode("utf-8"))
    except json.JSONDecodeError:
        pub_data = {}

    # --- Decrypt private metadata ---
    try:
        header_dict = json.loads(header_bytes.decode("utf-8"))
        iv = bytes.fromhex(header_dict["iv"])
        private_json = aes_decrypt(cipher_bytes, iv, stego_key)
        private_data = json.loads(private_json)
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"\n[ERROR] Decryption/parse failed: {exc}")
        return

    creator_credential = private_data.get("creator_credential", {})
    credential_history = private_data.get("credential_history", [])
    creator_email      = creator_credential.get("creator_email", "")

    # --- RBAC role determination ---
    role = determine_role(
        user_email=user_email or "",
        admin_key_input=admin_key_input or "",
        creator_email=creator_email,
        env_admin_key=env_admin_key or "",
    )

    # --- Render role-appropriate report ---
    if is_full_access(role):
        _render_full_report(integrity_label, role, pub_data, creator_credential, credential_history)
    else:
        _render_restricted_report(integrity_label, pub_data)
