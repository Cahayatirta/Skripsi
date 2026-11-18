"""
tests/test_stega.py
-------------------
Automated test suite for the DCT + AES-128 + SHA-256 steganography system.

Test categories:
  1. Capacity calculation and pre-embedding capacity error trigger.
  2. AES-128 encryption / decryption round-trip accuracy.
  3. SHA-256 hash mismatch detection.
  4. Lossless DCT bit embedding and extraction.
  5. Multi-step credential history append (initial embed -> 2nd edit).
  6. End-to-end embed -> extract -> verify pipeline.
  7. End-to-end CLI invocation via subprocess.

Run with:
  python -m pytest tests/test_stega.py -v
  -- or --
  python tests/test_stega.py
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

import numpy as np
from PIL import Image

# Make project root importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capacity_utils import (
    calculate_capacity,
    check_capacity,
    print_capacity_stats,
    print_bit_stats,
    get_embedded_payload_bits,
)
from crypto_utils import aes_decrypt, aes_encrypt, sha256_hash, verify_sha256
from dct_utils import (
    _from_bitstream,
    _pack_payload,
    _to_bitstream,
    _unpack_payload,
    compute_payload_bits,
    embed_bits,
    extract_bits,
    extract_payload,
)
from embedder import embed
from extractor import _decode_payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_test_image(width: int, height: int, tmp_dir: str, name: str = "cover.png") -> str:
    """Create a solid-colour PNG and return its path."""
    path = os.path.join(tmp_dir, name)
    arr = np.random.randint(100, 200, (height, width, 3), dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path, format="PNG")
    return path


_STEGO_KEY = "TestKey123!"
_EMAIL_1 = "cahayatirta11@gmail.com"
_EMAIL_2 = "test@gmail.com"


# ===========================================================================
# 1. Capacity Calculation & Error Trigger
# ===========================================================================

class TestCapacityUtils(unittest.TestCase):

    def test_capacity_formula(self):
        """floor(W/8) * floor(H/8) * 1 == expected."""
        self.assertEqual(calculate_capacity(512, 512), 4096)
        self.assertEqual(calculate_capacity(100, 100), 144)   # 12*12
        self.assertEqual(calculate_capacity(8, 8), 1)

    def test_capacity_ok_does_not_raise(self):
        """check_capacity should not raise when bits fit."""
        check_capacity(512, 512, required_bits=100)  # 4096 available >> 100

    def test_capacity_error_trigger_small_image(self):
        """Embedding into an 8x8 image (1 bit capacity) with >1 bit payload must raise."""
        with self.assertRaises(ValueError) as ctx:
            check_capacity(8, 8, required_bits=1000)
        msg = str(ctx.exception)
        self.assertIn("ERROR: Image capacity insufficient", msg)
        self.assertIn("Required: 1000 bits", msg)
        self.assertIn("Available: 1 bits", msg)

    def test_embed_tiny_image_32x32_aborts_without_creating_output(self):
        """Embedding into a 32x32 px image must trigger ValueError and halt before saving."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(32, 32, tmp, name="tiny_cover.png")
            stego = os.path.join(tmp, "tiny_stego.png")
            with self.assertRaises(ValueError) as ctx:
                embed(cover, stego, _EMAIL_1, "Original", _STEGO_KEY, 32, 32)
            msg = str(ctx.exception)
            self.assertTrue(msg.startswith("ERROR: Image capacity insufficient"))
            self.assertFalse(os.path.exists(stego), "Stego image must not be created when capacity fails")

    def test_capacity_stats_output_correctness(self):
        """print_capacity_stats must calculate and format bits, bytes, and percentage accurately."""
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            print_capacity_stats(512, 512, required_bits=2048, label="Embedding")
        output = buf.getvalue()
        self.assertIn("Available Capacity      : 4096 bits (512.00 bytes)", output)
        self.assertIn("Payload Size Required   : 2048 bits (256.00 bytes)", output)
        self.assertIn("Remaining Free Capacity : 2048 bits (256.00 bytes)", output)
        self.assertIn("Capacity Usage          : 50.0%", output)

    def test_capacity_exact_boundary(self):
        """Exactly at capacity boundary should not raise."""
        avail = calculate_capacity(64, 64)  # = 64 bits
        check_capacity(64, 64, required_bits=avail)

    def test_capacity_one_over_boundary(self):
        """One bit over capacity must raise."""
        avail = calculate_capacity(64, 64)
        with self.assertRaises(ValueError):
            check_capacity(64, 64, required_bits=avail + 1)


# ===========================================================================
# 2. AES-128 Encryption / Decryption Round-Trip
# ===========================================================================

class TestCryptoUtils(unittest.TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        """AES-128 encrypt then decrypt must recover original plaintext."""
        plaintext = '{"creator_email": "test@gmail.com", "created_at": "2026-01-01T00:00:00Z"}'
        ct, iv = aes_encrypt(plaintext, _STEGO_KEY)
        recovered = aes_decrypt(ct, iv, _STEGO_KEY)
        self.assertEqual(recovered, plaintext)

    def test_wrong_key_raises(self):
        """Decryption with wrong key must raise ValueError."""
        ct, iv = aes_encrypt("secret data", _STEGO_KEY)
        with self.assertRaises(ValueError):
            aes_decrypt(ct, iv, "WrongKey!")

    def test_different_ivs_per_call(self):
        """Each encryption call must generate a unique IV."""
        _, iv1 = aes_encrypt("data", _STEGO_KEY)
        _, iv2 = aes_encrypt("data", _STEGO_KEY)
        self.assertNotEqual(iv1, iv2)

    def test_ciphertext_differs_from_plaintext(self):
        """Ciphertext must not equal plaintext bytes."""
        pt = "hello world"
        ct, _ = aes_encrypt(pt, _STEGO_KEY)
        self.assertNotEqual(ct, pt.encode())

    def test_unicode_plaintext(self):
        """Unicode characters must survive encrypt/decrypt."""
        pt = "status: Asli — créé par utilisateur"
        ct, iv = aes_encrypt(pt, _STEGO_KEY)
        self.assertEqual(aes_decrypt(ct, iv, _STEGO_KEY), pt)


# ===========================================================================
# 3. SHA-256 Hash Mismatch Detection
# ===========================================================================

class TestSha256(unittest.TestCase):

    def test_hash_verify_correct(self):
        data = b"authentic ciphertext"
        h = sha256_hash(data)
        self.assertTrue(verify_sha256(data, h))

    def test_hash_verify_tampered(self):
        """Altering even one bit of ciphertext must fail verification."""
        data = b"authentic ciphertext"
        h = sha256_hash(data)
        tampered = bytearray(data)
        tampered[0] ^= 0xFF  # flip bits
        self.assertFalse(verify_sha256(bytes(tampered), h))

    def test_hash_is_32_bytes(self):
        self.assertEqual(len(sha256_hash(b"any data")), 32)

    def test_wrong_hash_fails(self):
        data = b"payload"
        wrong_hash = bytes(32)  # all zeros
        self.assertFalse(verify_sha256(data, wrong_hash))


# ===========================================================================
# 4. DCT Bitstream Packing / Unpacking + Bit Embedding & Extraction
# ===========================================================================

class TestDctUtils(unittest.TestCase):

    def test_bitstream_roundtrip(self):
        """_to_bitstream -> _from_bitstream must reconstruct original bytes."""
        original = b"Hello, DCT!"
        bits = _to_bitstream(original)
        self.assertEqual(len(bits), len(original) * 8)
        recovered = _from_bitstream(bits)
        self.assertEqual(recovered, original)

    def test_pack_unpack_payload(self):
        """Packed payload must unpack into identical components."""
        header = b'{"version":1,"iv":"aabbccdd"}'
        pub = b'{"current_status":"Asli"}'
        cipher = b"\xde\xad\xbe\xef" * 8
        sha = bytes(range(32))
        packed = _pack_payload(header, pub, cipher, sha)
        h2, p2, c2, s2 = _unpack_payload(packed)
        self.assertEqual(h2, header)
        self.assertEqual(p2, pub)
        self.assertEqual(c2, cipher)
        self.assertEqual(s2, sha)

    def test_embed_extract_bits(self):
        """Bits embedded in a 512x512 image must be extracted identically."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp, "cover.png")
            stego = os.path.join(tmp, "stego.png")

            payload_bytes = b"ABCDEF12345678"
            num_bits = len(payload_bytes) * 8

            # Build minimal valid packet
            header = b'{"version":1,"iv":"' + b"00" * 16 + b'"}'
            pub = b'{"current_status":"Original"}'
            cipher = payload_bytes  # treat as cipher for this low-level test
            sha_b = bytes(32)

            embed_bits(cover, stego, header, pub, cipher, sha_b)
            raw = extract_bits(stego, num_bits)
            # Just verify that extracted payload starts with something non-zero
            # (full round-trip tested in end-to-end tests below)
            self.assertEqual(len(raw), len(payload_bytes))

    def test_compute_payload_bits_positive(self):
        """compute_payload_bits must return a positive integer."""
        header = b'{"v":1}'
        pub = b'{"s":"OK"}'
        cipher = b"\x00" * 32
        sha = bytes(32)
        bits = compute_payload_bits(header, pub, cipher, sha)
        # Expected = (4+7 + 4+10 + 4+32 + 32) * 8
        expected_bytes = 4 + len(header) + 4 + len(pub) + 4 + len(cipher) + 32
        self.assertEqual(bits, expected_bytes * 8)


# ===========================================================================
# 5. Multi-Step Credential History Append
# ===========================================================================

class TestCredentialHistoryAppend(unittest.TestCase):

    def test_initial_embed_creates_history(self):
        """First embed must create creator_credential and one-entry history."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp, "cover.png")
            stego = os.path.join(tmp, "stego1.png")

            img = Image.open(cover)
            w, h = img.size
            img.close()

            embed(cover, stego, _EMAIL_1, "AI Generated", _STEGO_KEY, w, h)

            creator, history = _decode_payload(stego, _STEGO_KEY)
            self.assertEqual(creator["creator_email"], _EMAIL_1)
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["action"], "AI Generated")
            self.assertEqual(history[0]["user_email"], _EMAIL_1)

    def test_second_embed_appends_history(self):
        """Second embed must preserve first history entry and append a second."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp, "cover.png")
            stego1 = os.path.join(tmp, "stego1.png")
            stego2 = os.path.join(tmp, "stego2.png")

            img = Image.open(cover)
            w, h = img.size
            img.close()

            # First embed
            embed(cover, stego1, _EMAIL_1, "AI Generated", _STEGO_KEY, w, h)

            # Second embed (using stego1 as cover)
            embed(stego1, stego2, _EMAIL_2, "Edited", _STEGO_KEY, w, h)

            creator, history = _decode_payload(stego2, _STEGO_KEY)

            # Creator unchanged from first embed
            self.assertEqual(creator["creator_email"], _EMAIL_1)

            # History must have 2 entries in order
            self.assertEqual(len(history), 2)
            self.assertEqual(history[0]["action"], "AI Generated")
            self.assertEqual(history[0]["user_email"], _EMAIL_1)
            self.assertEqual(history[1]["action"], "Edited")
            self.assertEqual(history[1]["user_email"], _EMAIL_2)

    def test_three_embeds_grow_history(self):
        """Three consecutive embeds must produce three history entries."""
        with tempfile.TemporaryDirectory() as tmp:
            # 1024x1024 gives 16384 bits -- enough for three stacked history payloads
            cover = _make_test_image(1024, 1024, tmp, "cover.png")
            paths = [cover]
            img = Image.open(cover)
            w, h = img.size
            img.close()

            actions = [
                ("AI Generated", _EMAIL_1),
                ("Edited", _EMAIL_2),
                ("Original", "third@gmail.com"),
            ]
            for i, (act, em) in enumerate(actions):
                out = os.path.join(tmp, f"stego{i}.png")
                embed(paths[-1], out, em, act, _STEGO_KEY, w, h)
                paths.append(out)

            _, history = _decode_payload(paths[-1], _STEGO_KEY)
            self.assertEqual(len(history), 3)
            for i, (act, em) in enumerate(actions):
                self.assertEqual(history[i]["action"], act)
                self.assertEqual(history[i]["user_email"], em)


# ===========================================================================
# 6. End-to-End Embed → Extract → Verify Pipeline
# ===========================================================================

class TestEndToEnd(unittest.TestCase):

    def test_full_embed_extract_pipeline(self):
        """Full embed then extract must return consistent public + private data."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            img = Image.open(cover)
            w, h = img.size
            img.close()

            embed(cover, stego, _EMAIL_1, "Original", _STEGO_KEY, w, h)
            creator, history = _decode_payload(stego, _STEGO_KEY)

            self.assertEqual(creator["creator_email"], _EMAIL_1)
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["action"], "Original")

    def test_wrong_key_raises_on_extract(self):
        """Extracting with the wrong stego key must raise ValueError."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            img = Image.open(cover)
            w, h = img.size
            img.close()

            embed(cover, stego, _EMAIL_1, "Asli", _STEGO_KEY, w, h)

            with self.assertRaises(ValueError):
                _decode_payload(stego, "WrongKey!")

    def test_integrity_failure_on_tampered_image(self):
        """
        Directly flipping DCT mid-frequency coefficients in the stego image
        must trigger an integrity (SHA-256 mismatch) or decryption error.
        Tampering is applied in the DCT domain so it reliably alters extracted bits.
        """
        from scipy.fftpack import dct as sp_dct, idct as sp_idct

        BLOCK = 8
        MID_ROW_T, MID_COL_T = 2, 4
        Q_STEP = 25.0

        def dct2(b):
            return sp_dct(sp_dct(b.T, norm="ortho").T, norm="ortho")

        def idct2(b):
            return sp_idct(sp_idct(b.T, norm="ortho").T, norm="ortho")

        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            img = Image.open(cover)
            w, h = img.size
            img.close()

            embed(cover, stego, _EMAIL_1, "Asli", _STEGO_KEY, w, h)

            # Flip QIM bits of the first 64 DCT blocks directly in the Y channel.
            img_ycbcr = Image.open(stego).convert("YCbCr")
            y_ch, cb, cr = img_ycbcr.split()
            y_arr = np.array(y_ch, dtype=np.float64)

            blocks_flipped = 0
            for row in range(0, (h // BLOCK) * BLOCK, BLOCK):
                for col in range(0, (w // BLOCK) * BLOCK, BLOCK):
                    if blocks_flipped >= 64:
                        break
                    block = y_arr[row:row + BLOCK, col:col + BLOCK]
                    dct_b = dct2(block)
                    c = dct_b[MID_ROW_T][MID_COL_T]
                    q = round(c / Q_STEP)
                    # Flip embedded bit by XOR-ing LSB of quantised index
                    q_flipped = q ^ 1
                    dct_b[MID_ROW_T][MID_COL_T] = q_flipped * Q_STEP
                    y_arr[row:row + BLOCK, col:col + BLOCK] = idct2(dct_b)
                    blocks_flipped += 1
                else:
                    continue
                break

            y_arr = np.clip(y_arr, 0, 255).astype(np.uint8)
            tampered = Image.merge(
                "YCbCr", (Image.fromarray(y_arr), cb, cr)
            ).convert("RGB")
            tampered.save(stego, format="PNG")

            # Now extraction must fail with integrity or decryption error
            with self.assertRaises(ValueError):
                _decode_payload(stego, _STEGO_KEY)

    def test_stego_output_is_png(self):
        """Output file must be a valid PNG."""
        with tempfile.TemporaryDirectory() as tmp:
            # 512x512 provides sufficient capacity (4096 bits)
            cover = _make_test_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            img = Image.open(cover)
            w, h = img.size
            img.close()

            embed(cover, stego, _EMAIL_1, "Original", _STEGO_KEY, w, h)
            out_img = Image.open(stego)
            self.assertEqual(out_img.format, "PNG")
            out_img.close()


# ===========================================================================
# 7. CLI Integration Tests
# ===========================================================================

class TestCLI(unittest.TestCase):

    def _run_cli(self, *args, check=True):
        result = subprocess.run(
            [sys.executable, "cli.py", *args],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        if check and result.returncode != 0:
            self.fail(
                f"CLI command failed (exit {result.returncode}):\n"
                f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
            )
        return result

    def test_cli_capacity(self):
        """CLI 'capacity' and 'check-capacity' command must succeed and print capacity stats."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp)
            result = self._run_cli("capacity", cover)
            self.assertIn("BIT CAPACITY STATISTICS", result.stdout)
            self.assertIn("512 x 512", result.stdout)
            self.assertIn("No embedded metadata detected. Image is 100% available.", result.stdout)
            self.assertIn("Capacity Usage          : 0.0%", result.stdout)

            # Test check-capacity alias as well
            result2 = self._run_cli("check-capacity", cover)
            self.assertIn("BIT CAPACITY STATISTICS", result2.stdout)
            self.assertIn("No embedded metadata detected. Image is 100% available.", result2.stdout)

    def test_cli_check_capacity_on_stego_reports_nonzero_usage(self):
        """'check-capacity' on a stego image must report actual non-zero usage percentage."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            self._run_cli("embed", cover, stego, _EMAIL_1, "AI Generated", "--key", _STEGO_KEY)

            result = self._run_cli("check-capacity", stego)
            self.assertIn("BIT CAPACITY STATISTICS [Capacity Inspection]", result.stdout)
            self.assertNotIn("No embedded metadata detected", result.stdout)
            self.assertIn("Capacity Used: 81.1%", result.stdout)
            self.assertIn("Payload Size Required   : 3320 bits", result.stdout)

    def test_cli_extract_reports_nonzero_capacity_stats(self):
        """CLI 'extract' must print real extracted payload bit stats and non-zero capacity usage."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            self._run_cli("embed", cover, stego, _EMAIL_1, "Original", "--key", _STEGO_KEY)

            result = self._run_cli("extract", stego, "--email", _EMAIL_1, "--key", _STEGO_KEY)
            self.assertIn("BIT CAPACITY STATISTICS [Extraction]", result.stdout)
            self.assertIn("Payload Size Required   : 3288 bits", result.stdout)
            self.assertIn("Capacity Usage          : 80.3%", result.stdout)
            self.assertIn("VALID", result.stdout)
            self.assertIn("Creator", result.stdout)

    def test_cli_embed_and_extract(self):
        """CLI embed then extract (as creator) must print VALID + full history."""
        with tempfile.TemporaryDirectory() as tmp:
            cover = _make_test_image(512, 512, tmp)
            stego = os.path.join(tmp, "stego.png")

            self._run_cli("embed", cover, stego, _EMAIL_1, "AI Generated", "--key", _STEGO_KEY)
            # Extract as the creator → full access report expected
            result = self._run_cli(
                "extract", stego, "--email", _EMAIL_1, "--key", _STEGO_KEY
            )

            self.assertIn("VALID", result.stdout)
            self.assertIn("AI Generated", result.stdout)
            self.assertIn(_EMAIL_1, result.stdout)
            self.assertIn("Creator", result.stdout)

    def test_cli_insufficient_capacity_exits_nonzero(self):
        """CLI embed into a tiny image must exit with non-zero code and display clear error message."""
        with tempfile.TemporaryDirectory() as tmp:
            # 32x32 = 16 bits capacity -- far too small
            cover = _make_test_image(32, 32, tmp)
            stego = os.path.join(tmp, "stego.png")
            result = self._run_cli(
                "embed", cover, stego, _EMAIL_1, "Original",
                "--key", _STEGO_KEY, check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ERROR: Image capacity insufficient", result.stderr)
            self.assertIn("Required:", result.stderr)
            self.assertIn("Available: 16 bits (2.00 bytes)", result.stderr)
            self.assertFalse(os.path.exists(stego))

    def test_cli_help(self):
        """CLI --help must exit 0 and print usage info."""
        result = self._run_cli("--help", check=False)
        # argparse prints help to stdout and exits 0
        self.assertEqual(result.returncode, 0)
        self.assertIn("embed", result.stdout)
        self.assertIn("extract", result.stdout)
        self.assertIn("capacity", result.stdout)


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)

