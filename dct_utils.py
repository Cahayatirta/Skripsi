"""
dct_utils.py
------------
Low-level DCT-domain bit embedding and extraction using scipy.fftpack.

Bitstream layout (all big-endian uint32 length prefixes):
  [4B header_len][header_bytes][4B pub_len][pub_bytes][4B cipher_len][cipher_bytes][32B sha256]

Embedding strategy:
  - Convert image to YCbCr, operate on Y (luma) channel.
  - Divide Y into non-overlapping 8x8 blocks.
  - Apply 2D DCT-II to each block.
  - Target mid-frequency coefficient at position [2][4] (zigzag index ~18).
  - QIM-style: quantise coefficient with step=25; set LSB of rounded quotient to 0/1.
  - Apply IDCT and reconstruct image.
"""

import struct
import numpy as np
from PIL import Image
from scipy.fftpack import dct, idct

# Mid-frequency coefficient position within an 8x8 block
MID_ROW: int = 2
MID_COL: int = 4
QUANTIZATION_STEP: float = 25.0
BLOCK: int = 8


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _dct2(block: np.ndarray) -> np.ndarray:
    """2D DCT-II via two separable 1D DCT passes."""
    return dct(dct(block.T, norm="ortho").T, norm="ortho")


def _idct2(block: np.ndarray) -> np.ndarray:
    """2D IDCT-II (inverse of _dct2)."""
    return idct(idct(block.T, norm="ortho").T, norm="ortho")


def _to_bitstream(data: bytes) -> list:
    """Convert bytes to a list of integer bits (MSB-first per byte)."""
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _from_bitstream(bits: list) -> bytes:
    """Convert a list of integer bits (MSB-first per byte) to bytes."""
    if len(bits) % 8 != 0:
        raise ValueError("Bit list length must be a multiple of 8.")
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for shift, b in enumerate(bits[i : i + 8]):
            byte |= (b & 1) << (7 - shift)
        result.append(byte)
    return bytes(result)


def _pack_payload(
    header_bytes: bytes,
    pub_bytes: bytes,
    cipher_bytes: bytes,
    sha256_bytes: bytes,
) -> bytes:
    """
    Pack all components into the binary payload:
      [4B header_len][header][4B pub_len][pub][4B cipher_len][cipher][32B hash]
    """
    return (
        struct.pack(">I", len(header_bytes)) + header_bytes
        + struct.pack(">I", len(pub_bytes)) + pub_bytes
        + struct.pack(">I", len(cipher_bytes)) + cipher_bytes
        + sha256_bytes
    )


def _unpack_payload(
    payload: bytes,
) -> tuple:
    """
    Unpack binary payload into (header_bytes, pub_bytes, cipher_bytes, sha256_bytes).
    """
    offset = 0

    def read_segment(buf: bytes, pos: int):
        if pos + 4 > len(buf):
            raise ValueError("Payload truncated while reading length prefix.")
        length = struct.unpack(">I", buf[pos : pos + 4])[0]
        pos += 4
        if pos + length > len(buf):
            raise ValueError(f"Payload truncated: expected {length} bytes.")
        return buf[pos : pos + length], pos + length

    header_bytes, offset = read_segment(payload, offset)
    pub_bytes, offset = read_segment(payload, offset)
    cipher_bytes, offset = read_segment(payload, offset)

    if offset + 32 > len(payload):
        raise ValueError("Payload truncated while reading SHA-256 hash.")
    sha256_bytes = payload[offset : offset + 32]

    return header_bytes, pub_bytes, cipher_bytes, sha256_bytes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def embed_bits(
    image_path: str,
    output_path: str,
    header_bytes: bytes,
    pub_bytes: bytes,
    cipher_bytes: bytes,
    sha256_bytes: bytes,
) -> int:
    """
    Embed the packed payload into *image_path* and save to *output_path*.

    Returns the total number of bits embedded.

    Raises:
        ValueError: if image capacity is insufficient (checked externally via
                    capacity_utils.check_capacity before calling this function).
    """
    payload = _pack_payload(header_bytes, pub_bytes, cipher_bytes, sha256_bytes)
    bits = _to_bitstream(payload)
    total_bits = len(bits)

    img = Image.open(image_path).convert("RGB")
    img_ycbcr = img.convert("YCbCr")
    y_channel, cb, cr = img_ycbcr.split()

    y_array = np.array(y_channel, dtype=np.float64)
    h, w = y_array.shape
    bit_idx = 0

    for row in range(0, (h // BLOCK) * BLOCK, BLOCK):
        for col in range(0, (w // BLOCK) * BLOCK, BLOCK):
            if bit_idx >= total_bits:
                break
            block = y_array[row : row + BLOCK, col : col + BLOCK]
            dct_block = _dct2(block)

            # QIM embedding: quantise target coefficient, set LSB of quotient
            coeff = dct_block[MID_ROW][MID_COL]
            q = round(coeff / QUANTIZATION_STEP)
            if q % 2 != bits[bit_idx]:
                q += 1 if bits[bit_idx] == 1 else -1
            dct_block[MID_ROW][MID_COL] = q * QUANTIZATION_STEP

            y_array[row : row + BLOCK, col : col + BLOCK] = _idct2(dct_block)
            bit_idx += 1
        else:
            continue
        break

    # Clip to valid pixel range and reconstruct
    y_array = np.clip(y_array, 0, 255).astype(np.uint8)
    stego_ycbcr = Image.merge("YCbCr", (Image.fromarray(y_array), cb, cr))
    stego_rgb = stego_ycbcr.convert("RGB")
    stego_rgb.save(output_path, format="PNG")

    return total_bits


def extract_bits(image_path: str, num_bits: int) -> bytes:
    """
    Extract *num_bits* from the DCT mid-frequency coefficients and return
    the reconstructed payload bytes.
    """
    img = Image.open(image_path).convert("RGB")
    img_ycbcr = img.convert("YCbCr")
    y_channel, _, _ = img_ycbcr.split()

    y_array = np.array(y_channel, dtype=np.float64)
    h, w = y_array.shape
    bits = []

    for row in range(0, (h // BLOCK) * BLOCK, BLOCK):
        for col in range(0, (w // BLOCK) * BLOCK, BLOCK):
            if len(bits) >= num_bits:
                break
            block = y_array[row : row + BLOCK, col : col + BLOCK]
            dct_block = _dct2(block)
            coeff = dct_block[MID_ROW][MID_COL]
            q = round(coeff / QUANTIZATION_STEP)
            bits.append(q % 2)
        else:
            continue
        break

    return _from_bitstream(bits[:num_bits])


def extract_payload(image_path: str) -> tuple:
    """
    Extract and unpack all payload components from a stego image.

    Returns (header_bytes, pub_bytes, cipher_bytes, sha256_bytes).

    Raises:
        ValueError: if the payload cannot be parsed (no valid stego data).
    """
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    max_bits = (w // BLOCK) * (h // BLOCK)
    max_bytes = max_bits // 8

    # Read full payload region
    raw = extract_bits(image_path, max_bits)

    # Attempt parse: first 4 bytes = header_len
    try:
        header_len = struct.unpack(">I", raw[:4])[0]
        # Sanity check: header should be small (< 256 bytes)
        if header_len == 0 or header_len > 256:
            raise ValueError("Invalid header length — no valid stego payload detected.")
        return _unpack_payload(raw)
    except struct.error as exc:
        raise ValueError(f"Failed to parse payload: {exc}") from exc


def compute_payload_bits(
    header_bytes: bytes,
    pub_bytes: bytes,
    cipher_bytes: bytes,
    sha256_bytes: bytes,
) -> int:
    """Return total bit length of the assembled payload."""
    payload = _pack_payload(header_bytes, pub_bytes, cipher_bytes, sha256_bytes)
    return len(payload) * 8
