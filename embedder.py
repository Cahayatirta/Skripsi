"""
embedder.py
-----------
Module 1: Secure Metadata Embedding & Append Pipeline.

Workflow:
  1. Attempt to extract existing payload from input image.
  2. If found: append new entry to credential_history.
     If not found: initialise creator_credential + credential_history.
  3. Build public + private metadata dicts.
  4. Encrypt private metadata (AES-128-CBC) + compute SHA-256 over ciphertext.
  5. Pack payload, validate capacity, embed via DCT, save PNG.
"""

import json
from datetime import datetime, timezone

from crypto_utils import aes_encrypt, sha256_hash
from dct_utils import embed_bits, extract_payload, compute_payload_bits
from capacity_utils import check_capacity, print_capacity_stats, print_bit_stats

try:
    from extractor import _decode_payload  # avoid circular: use internal helper
except ImportError:
    _decode_payload = None

VALID_STATUSES = {"AI Generated", "Edited", "Original", "Asli"}


def _current_iso_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _try_extract_existing(image_path: str, stego_key: str):
    """
    Attempt to extract and decrypt existing embedded metadata.

    Returns (creator_credential dict, credential_history list) or
    (None, None) if no valid stego payload is found.
    """
    try:
        from extractor import _decode_payload as decode
        return decode(image_path, stego_key)
    except Exception:
        return None, None


def embed(
    cover_path: str,
    output_path: str,
    user_email: str,
    status: str,
    stego_key: str,
    image_width: int,
    image_height: int,
) -> None:
    """
    Full embedding pipeline.

    Args:
        cover_path:   Path to the cover (or existing stego) image.
        output_path:  Destination path for the stego PNG.
        user_email:   Gmail address of the current operator.
        status:       One of 'AI Generated', 'Edited', 'Original', 'Asli'.
        stego_key:    Secret key string for AES + DCT operations.
        image_width:  Pixel width of the cover image.
        image_height: Pixel height of the cover image.

    Raises:
        ValueError: On invalid status or insufficient image capacity.
    """
    if status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid status '{status}'. Must be one of: {sorted(VALID_STATUSES)}"
        )

    now_ts = _current_iso_timestamp()

    # ------------------------------------------------------------------
    # Step 1: Check for existing embedded payload → append history
    # ------------------------------------------------------------------
    creator_credential, credential_history = _try_extract_existing(cover_path, stego_key)

    if creator_credential is None:
        # First-time embedding
        creator_credential = {
            "creator_email": user_email,
            "created_at": now_ts,
        }
        credential_history = []

    # Append current action
    credential_history.append(
        {
            "action": status,
            "user_email": user_email,
            "timestamp": now_ts,
        }
    )

    # ------------------------------------------------------------------
    # Step 2: Build metadata payloads
    # ------------------------------------------------------------------
    public_metadata = {
        "current_status": status,
        "last_modified_by": user_email,
    }

    private_metadata = {
        "creator_credential": creator_credential,
        "credential_history": credential_history,
    }

    # ------------------------------------------------------------------
    # Step 3: Encrypt private metadata + compute integrity hash
    # ------------------------------------------------------------------
    private_json = json.dumps(private_metadata, ensure_ascii=False)
    ciphertext, iv = aes_encrypt(private_json, stego_key)
    integrity_hash = sha256_hash(ciphertext)

    # Header carries AES IV for decryption
    header_dict = {"version": 1, "iv": iv.hex()}
    header_bytes = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")

    pub_bytes = json.dumps(public_metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    cipher_bytes = ciphertext
    sha256_bytes = integrity_hash  # exactly 32 bytes

    # ------------------------------------------------------------------
    # Step 4: Capacity validation + stats
    # ------------------------------------------------------------------
    required_bits = compute_payload_bits(header_bytes, pub_bytes, cipher_bytes, sha256_bytes)

    # 1. Capacity check FIRST: immediately abort if image capacity is insufficient
    check_capacity(image_width, image_height, required_bits)

    # 2. Display capacity stats BEFORE embedding
    print_capacity_stats(image_width, image_height, required_bits, label="Embedding")

    # ------------------------------------------------------------------
    # Step 5: DCT embedding → save lossless PNG
    # ------------------------------------------------------------------
    total_bits_embedded = embed_bits(
        cover_path,
        output_path,
        header_bytes,
        pub_bytes,
        cipher_bytes,
        sha256_bytes,
    )

    # 3. Display capacity stats AFTER embedding
    print_capacity_stats(image_width, image_height, required_bits, label="Embedding")

    print(f"\n[OK] Embedding complete.")
    print(f"     Output : {output_path}")
    print(f"     Bits embedded : {total_bits_embedded}")
    print(f"     Status  : {status}")
    print(f"     User    : {user_email}")
    print(f"     Timestamp: {now_ts}")
