"""
capacity_utils.py
-----------------
DCT capacity calculation and bit-statistics reporting.
"""

import math
from typing import Optional


BITS_PER_BLOCK: int = 1  # bits embedded per 8x8 DCT block (default: 1)
BLOCK_SIZE: int = 8


def calculate_capacity(width: int, height: int, bits_per_block: int = BITS_PER_BLOCK) -> int:
    """
    Return maximum embeddable bits for an image of given dimensions.

    Formula: floor(W/8) * floor(H/8) * bits_per_block
    """
    return (width // BLOCK_SIZE) * (height // BLOCK_SIZE) * bits_per_block


def check_capacity(
    width: int,
    height: int,
    required_bits: int,
    bits_per_block: int = BITS_PER_BLOCK,
) -> None:
    """
    Assert that the image can hold *required_bits*.

    Raises:
        ValueError: with a descriptive abort message if capacity is insufficient.
    """
    available = calculate_capacity(width, height, bits_per_block)
    if required_bits > available:
        req_bytes = required_bits / 8
        avail_bytes = available / 8
        raise ValueError(
            f"ERROR: Image capacity insufficient. "
            f"Required: {required_bits} bits ({req_bytes:.2f} bytes), "
            f"Available: {available} bits ({avail_bytes:.2f} bytes). "
            f"Please use a larger image or reduce metadata length."
        )


def print_capacity_stats(
    width: int,
    height: int,
    required_bits: int,
    bits_per_block: int = BITS_PER_BLOCK,
    label: str = "Embedding",
) -> None:
    """
    Print a formatted real-time capacity statistics table to stdout.
    """
    blocks_h = width // BLOCK_SIZE
    blocks_v = height // BLOCK_SIZE
    total_blocks = blocks_h * blocks_v
    available_bits = total_blocks * bits_per_block
    available_bytes = available_bits / 8
    required_bytes = required_bits / 8
    remaining_bits = available_bits - required_bits
    remaining_bytes = remaining_bits / 8
    usage_pct = (required_bits / available_bits * 100) if available_bits > 0 else 0.0

    sep = "=" * 54
    print(sep)
    print(f"  BIT CAPACITY STATISTICS [{label}]")
    print(sep)
    print(f"  Image Dimensions        : {width} x {height} px")
    print(f"  8x8 Blocks (H x V)      : {blocks_h} x {blocks_v} = {total_blocks} blocks")
    print(f"  Bits Per Block          : {bits_per_block}")
    print(f"  Available Capacity      : {available_bits} bits ({available_bytes:.2f} bytes)")
    print(f"  Payload Size Required   : {required_bits} bits ({required_bytes:.2f} bytes)")
    print(f"  Remaining Free Capacity : {remaining_bits} bits ({remaining_bytes:.2f} bytes)")
    print(f"  Capacity Usage          : {usage_pct:.1f}%")
    print(sep)


# Alias for backward-compatibility
print_bit_stats = print_capacity_stats


def get_embedded_payload_bits(image_path: str) -> int:
    """
    Inspect the image for an existing DCT embedded payload header.
    Returns the total number of bits embedded if valid, or 0 if not found.
    """
    try:
        import json
        from dct_utils import extract_payload, compute_payload_bits

        header_bytes, pub_bytes, cipher_bytes, sha256_bytes = extract_payload(image_path)
        header_dict = json.loads(header_bytes.decode("utf-8"))
        if "version" in header_dict and len(sha256_bytes) == 32:
            return compute_payload_bits(header_bytes, pub_bytes, cipher_bytes, sha256_bytes)
    except Exception:
        pass
    return 0


# Alias for capacity inspection
inspect_capacity = get_embedded_payload_bits

