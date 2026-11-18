"""
cli.py
------
CLI entry point for the DCT + AES-128 + SHA-256 steganography tool.

Commands:
  embed     -- Embed metadata into a cover image (or append to existing stego).
  extract   -- Extract and verify metadata from a stego image (RBAC-gated).
  capacity  -- Display DCT capacity stats for an image without embedding.

Key management (priority order):
  1. --key <KEY>      explicit CLI override
  2. STEGO_SECRET_KEY from .env
  3. Auto-generated (saved to .env on first run)

Usage examples:
  python cli.py embed cover.png stego.png cahayatirta11@gmail.com "AI Generated"
  python cli.py embed cover.png stego.png user@gmail.com "Edited" --key MyOverrideKey
  python cli.py extract stego.png --email cahayatirta11@gmail.com
  python cli.py extract stego.png --email guest@gmail.com --admin-key AdminPass
  python cli.py capacity cover.png
"""

import sys
import argparse
from PIL import Image

from env_utils import load_env, get_stego_key, get_admin_key
from embedder import embed
from extractor import extract_and_verify
from capacity_utils import (
    print_capacity_stats,
    print_bit_stats,
    calculate_capacity,
    get_embedded_payload_bits,
)

VALID_STATUSES = ("AI Generated", "Edited", "Original", "Asli")


def cmd_embed(args) -> int:
    """Handle the 'embed' sub-command."""
    stego_key = get_stego_key(override=args.key)

    img = Image.open(args.cover_image)
    w, h = img.size
    img.close()

    try:
        embed(
            cover_path=args.cover_image,
            output_path=args.output_image,
            user_email=args.email,
            status=args.status,
            stego_key=stego_key,
            image_width=w,
            image_height=h,
        )
    except ValueError as exc:
        msg = str(exc)
        if not msg.startswith("ERROR:"):
            msg = f"ERROR: {msg}"
        print(f"\n{msg}", file=sys.stderr)
        return 1
    return 0


def cmd_extract(args) -> int:
    """Handle the 'extract' sub-command."""
    stego_key    = get_stego_key(override=args.key)
    env_admin    = get_admin_key()
    admin_input  = getattr(args, "admin_key", None) or ""

    try:
        extract_and_verify(
            image_path=args.stego_image,
            stego_key=stego_key,
            user_email=getattr(args, "email", None),
            admin_key_input=admin_input,
            env_admin_key=env_admin,
        )
    except Exception as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_capacity(args) -> int:
    """Handle the 'capacity' / 'check-capacity' sub-command."""
    img = Image.open(args.image)
    w, h = img.size
    img.close()

    embedded_bits = get_embedded_payload_bits(args.image)
    if embedded_bits > 0:
        print_capacity_stats(w, h, required_bits=embedded_bits, label="Capacity Inspection")
        avail = calculate_capacity(w, h)
        usage_pct = (embedded_bits / avail * 100) if avail > 0 else 0.0
        print(f"  Capacity Used: {usage_pct:.1f}%")
    else:
        print_capacity_stats(w, h, required_bits=0, label="Capacity Inspection")
        avail = calculate_capacity(w, h)
        print("  No embedded metadata detected. Image is 100% available.")
        print(f"  Maximum payload : {avail // 8} bytes ({avail} bits)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegacrypt",
        description="DCT + AES-128 + SHA-256 Steganography CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ----------------------------------------------------------------
    # embed
    # ----------------------------------------------------------------
    p_embed = sub.add_parser("embed", help="Embed metadata into a cover image.")
    p_embed.add_argument("cover_image",  help="Path to cover (or existing stego) image.")
    p_embed.add_argument("output_image", help="Destination path for the stego PNG.")
    p_embed.add_argument("email",        help="Gmail address of the current operator.")
    p_embed.add_argument(
        "status",
        choices=VALID_STATUSES,
        help="Image classification status.",
    )
    p_embed.add_argument(
        "--key", "-k",
        default=None,
        metavar="KEY",
        help="Override STEGO_SECRET_KEY from .env (optional).",
    )

    # ----------------------------------------------------------------
    # extract
    # ----------------------------------------------------------------
    p_extract = sub.add_parser(
        "extract", help="Extract and verify metadata from a stego image."
    )
    p_extract.add_argument("stego_image", help="Path to the stego image.")
    p_extract.add_argument(
        "--email", "-e",
        default=None,
        metavar="EMAIL",
        help="Your Gmail address for Creator role verification.",
    )
    p_extract.add_argument(
        "--admin-key", "-a",
        default=None,
        metavar="ADMIN_KEY",
        dest="admin_key",
        help="Admin key to unlock full private metadata (matches ADMIN_KEY in .env).",
    )
    p_extract.add_argument(
        "--key", "-k",
        default=None,
        metavar="KEY",
        help="Override STEGO_SECRET_KEY from .env (optional).",
    )

    # ----------------------------------------------------------------
    # capacity / check-capacity
    # ----------------------------------------------------------------
    p_cap = sub.add_parser(
        "check-capacity",
        aliases=["capacity"],
        help="Display DCT capacity stats for an image.",
    )
    p_cap.add_argument("image", help="Path to the target image.")

    return parser


def main() -> None:
    # Auto-load .env on every invocation (generates keys if absent)
    load_env()

    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "embed":          cmd_embed,
        "extract":        cmd_extract,
        "check-capacity": cmd_capacity,
        "capacity":       cmd_capacity,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
