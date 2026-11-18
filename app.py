"""
app.py
------
Streamlit Web UI for DCT Steganography & Provenance Verification.
Features:
- Full Authentication System (Login, Registration, SQLite persistence).
- Gmail Email Verification with 6-digit OTP (5-minute expiration & dev fallback mode).
- Absolute Stego-Key isolation (read silently from .env in backend).
- Streamlined metadata input controls (AI Generated, Edited, Original).
- Role-Based Access Control (RBAC) with conditional Admin Secret Key verification.
- Real-time bit capacity analysis and capacity guard.
"""

import io
import json
import os
import tempfile
import time
from typing import List

import pandas as pd
from PIL import Image
import streamlit as st

# Backend logic & environment (strictly preserved)
from env_utils import load_env, get_stego_key, get_admin_key
from embedder import (
    embed,
    _try_extract_existing,
    _current_iso_timestamp,
)
from crypto_utils import aes_encrypt, sha256_hash, aes_decrypt, verify_sha256
from dct_utils import extract_payload, compute_payload_bits
from capacity_utils import (
    calculate_capacity,
    get_embedded_payload_bits,
    BLOCK_SIZE,
)
from rbac_utils import Role, determine_role, is_full_access, role_label

# Authentication & OTP utilities
from auth_utils import (
    init_db,
    register_user,
    authenticate_user,
    mark_user_verified,
    generate_otp,
    is_otp_valid,
    send_otp_email,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
UI_STATUS_CHOICES: List[str] = ["AI Generated", "Edited", "Original"]
ADMIN_EMAIL: str = "admin@gmail.com"

# ---------------------------------------------------------------------------
# Streamlit Page Config & Styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="DCT Steganography & Provenance Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize backend environment and user database
load_env()
init_db()


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
def format_timestamp(ts_raw: str) -> str:
    """Format ISO UTC timestamp string into readable UTC format."""
    try:
        from datetime import datetime, timezone
        dt = datetime.strptime(ts_raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts_raw)


def compute_preview_payload_bits(
    cover_path: str,
    user_email: str,
    status: str,
) -> int:
    """
    Simulate required payload bit length using the backend STEGO_SECRET_KEY.
    The secret key is loaded internally and never exposed to the frontend.
    """
    stego_key = get_stego_key()
    now_ts = _current_iso_timestamp()
    creator_credential, credential_history = _try_extract_existing(cover_path, stego_key)

    if creator_credential is None:
        creator_credential = {
            "creator_email": user_email,
            "created_at": now_ts,
        }
        credential_history = []

    sim_history = list(credential_history)
    sim_history.append(
        {
            "action": status,
            "user_email": user_email,
            "timestamp": now_ts,
        }
    )

    public_metadata = {
        "current_status": status,
        "last_modified_by": user_email,
    }

    private_metadata = {
        "creator_credential": creator_credential,
        "credential_history": sim_history,
    }

    private_json = json.dumps(private_metadata, ensure_ascii=False)
    ciphertext, iv = aes_encrypt(private_json, stego_key)
    integrity_hash = sha256_hash(ciphertext)

    header_dict = {"version": 1, "iv": iv.hex()}
    header_bytes = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
    pub_bytes = json.dumps(public_metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    cipher_bytes = ciphertext
    sha256_bytes = integrity_hash

    return compute_payload_bits(header_bytes, pub_bytes, cipher_bytes, sha256_bytes)


# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "user_email" not in st.session_state:
    st.session_state["user_email"] = ""
if "is_admin" not in st.session_state:
    st.session_state["is_admin"] = False
if "auth_mode" not in st.session_state:
    st.session_state["auth_mode"] = "login"  # 'login', 'register', or 'otp'
if "otp_email" not in st.session_state:
    st.session_state["otp_email"] = ""
if "otp_code" not in st.session_state:
    st.session_state["otp_code"] = ""
if "otp_expires_at" not in st.session_state:
    st.session_state["otp_expires_at"] = 0.0
if "otp_dev_notice" not in st.session_state:
    st.session_state["otp_dev_notice"] = ""


# ===========================================================================
# 1. AUTHENTICATION & EMAIL VERIFICATION GATEWAY
# ===========================================================================
if not st.session_state["logged_in"]:
    st.title("🛡️ DCT Steganography System - Portal Autentikasi")
    st.markdown(
        "Akses aman ke modul steganografi frekuensi DCT, enkripsi AES-128, "
        "dan verifikasi integritas citra berbasis peran (RBAC)."
    )
    st.markdown("---")

    col_center = st.columns([1, 2, 1])[1]

    with col_center:
        # Check if in OTP verification mode
        if st.session_state["auth_mode"] == "otp":
            st.subheader("📬 Verifikasi Kode OTP Email")
            st.markdown(
                f"Kode verifikasi telah dikirimkan ke **{st.session_state['otp_email']}**. "
                f"Kode ini berlaku selama **5 menit**."
            )

            # Display dev fallback notice if active
            if st.session_state["otp_dev_notice"]:
                st.info(f"💡 {st.session_state['otp_dev_notice']}")

            entered_otp = st.text_input(
                "Masukkan 6-Digit Kode OTP:",
                max_chars=6,
                placeholder="123456",
                key="input_entered_otp",
            )

            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("✅ Verifikasi Akun", type="primary", use_container_width=True):
                    valid, msg = is_otp_valid(
                        entered_otp,
                        st.session_state["otp_code"],
                        st.session_state["otp_expires_at"],
                    )
                    if valid:
                        mark_user_verified(st.session_state["otp_email"])
                        st.success("🎉 Verifikasi Berhasil! Akun Anda telah aktif. Silakan login.")
                        st.session_state["auth_mode"] = "login"
                        st.session_state["otp_code"] = ""
                        st.session_state["otp_dev_notice"] = ""
                        time.sleep(1.2)
                        st.rerun()
                    else:
                        st.error(f"❌ {msg}")

            with col_btn2:
                if st.button("🔄 Kirim Ulang OTP", use_container_width=True):
                    new_otp, new_exp = generate_otp()
                    st.session_state["otp_code"] = new_otp
                    st.session_state["otp_expires_at"] = new_exp
                    _, send_msg = send_otp_email(st.session_state["otp_email"], new_otp)
                    st.session_state["otp_dev_notice"] = send_msg
                    st.success("Kode OTP baru telah digenerate!")
                    st.rerun()

            if st.button("⬅️ Kembali ke Menu Login", use_container_width=True):
                st.session_state["auth_mode"] = "login"
                st.rerun()

        else:
            # Login / Register Mode Tabs
            auth_tab_login, auth_tab_register = st.tabs(["🔐 Masuk / Login", "📝 Registrasi Akun Baru"])

            # --- SUB-TAB: LOGIN ---
            with auth_tab_login:
                st.markdown("### Masuk ke Akun Anda")
                login_email = st.text_input(
                    "Alamat Email Gmail:",
                    placeholder="user@gmail.com atau admin@gmail.com",
                    key="login_email_input",
                )
                login_password = st.text_input(
                    "Password:",
                    type="password",
                    placeholder="Masukkan password Anda...",
                    key="login_password_input",
                )

                if st.button("🚀 Masuk", type="primary", use_container_width=True):
                    success, msg, is_admin = authenticate_user(login_email, login_password)
                    if success:
                        st.session_state["logged_in"] = True
                        st.session_state["user_email"] = login_email.strip().lower()
                        st.session_state["is_admin"] = is_admin
                        st.success("Login berhasil!")
                        st.rerun()
                    else:
                        if "belum diverifikasi" in msg:
                            st.warning("Akun ini belum diverifikasi. Kode OTP baru sedang dikirimkan...")
                            new_otp, new_exp = generate_otp()
                            st.session_state["otp_email"] = login_email.strip().lower()
                            st.session_state["otp_code"] = new_otp
                            st.session_state["otp_expires_at"] = new_exp
                            _, send_msg = send_otp_email(login_email, new_otp)
                            st.session_state["otp_dev_notice"] = send_msg
                            st.session_state["auth_mode"] = "otp"
                            st.rerun()
                        else:
                            st.error(f"❌ {msg}")

                st.caption("Default Admin: `admin@gmail.com` | Password: `admin`")

            # --- SUB-TAB: REGISTRATION ---
            with auth_tab_register:
                st.markdown("### Buat Akun Baru")
                st.info("Pendaftaran mewajibkan alamat Gmail (@gmail.com) untuk verifikasi kode OTP.")

                reg_email = st.text_input(
                    "Alamat Gmail:",
                    placeholder="namaanda@gmail.com",
                    key="reg_email_input",
                )
                reg_password = st.text_input(
                    "Password Baru:",
                    type="password",
                    placeholder="Minimal 4 karakter...",
                    key="reg_password_input",
                )
                reg_confirm = st.text_input(
                    "Konfirmasi Password:",
                    type="password",
                    placeholder="Ulangi password baru...",
                    key="reg_confirm_input",
                )

                if st.button("📩 Daftar & Kirim Kode OTP", type="primary", use_container_width=True):
                    if reg_password != reg_confirm:
                        st.error("Konfirmasi password tidak cocok.")
                    else:
                        reg_ok, reg_msg = register_user(reg_email, reg_password)
                        if reg_ok:
                            # Generate and dispatch OTP
                            otp_code, expires_at = generate_otp()
                            st.session_state["otp_email"] = reg_email.strip().lower()
                            st.session_state["otp_code"] = otp_code
                            st.session_state["otp_expires_at"] = expires_at

                            _, send_msg = send_otp_email(reg_email, otp_code)
                            st.session_state["otp_dev_notice"] = send_msg
                            st.session_state["auth_mode"] = "otp"
                            st.success(reg_msg)
                            time.sleep(0.8)
                            st.rerun()
                        else:
                            st.error(f"❌ {reg_msg}")

    st.stop()


# ===========================================================================
# 2. MAIN APP LAYOUT (Post-Login)
# ===========================================================================

# --- SIDEBAR ---
with st.sidebar:
    st.title("👤 Profil Pengguna")
    st.markdown(f"**Email Aktif:** `{st.session_state['user_email']}`")

    if st.session_state["is_admin"]:
        st.success("🛡️ **[ROLE: ADMIN]**")
    else:
        st.info("👤 **[ROLE: USER]**")

    st.markdown("---")
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state["logged_in"] = False
        st.session_state["user_email"] = ""
        st.session_state["is_admin"] = False
        st.session_state["auth_mode"] = "login"
        st.rerun()

    st.markdown("---")
    st.caption("Steganografi Domain Frekuensi DCT dengan Integritas SHA-256 dan Enkripsi AES-128.")


# --- MAIN CONTENT TABS ---
st.title("🛡️ DCT Steganography & Digital Provenance Suite")
st.caption(f"Operator: **{st.session_state['user_email']}** | Akses: **{'Admin' if st.session_state['is_admin'] else 'Regular User'}**")

tab1, tab2, tab3 = st.tabs([
    "📥 Embed Metadata",
    "🔍 Extract & Verify",
    "📊 Capacity Inspector",
])


# ===========================================================================
# TAB 1: Embed Metadata
# ===========================================================================
with tab1:
    st.header("📥 Sisipkan Metadata Provenance")
    st.markdown("Sisipkan identitas operator, status klasifikasi, dan riwayat revisi ke dalam koefisien frekuensi menengah DCT citra.")

    col_up, col_ctrl = st.columns([1, 1], gap="medium")

    with col_up:
        cover_file = st.file_uploader(
            "Pilih Cover Image (atau gambar stego sebelumnya untuk append):",
            type=["png", "jpg", "jpeg"],
            key="tab1_cover_uploader",
        )
        if cover_file is not None:
            cover_img = Image.open(cover_file)
            st.image(
                cover_img,
                caption=f"Cover: {cover_file.name} ({cover_img.width} × {cover_img.height} px)",
                use_container_width=True,
            )

    with col_ctrl:
        st.subheader("Parameter Penyisipan")
        status_choice = st.selectbox(
            "Pilih Status Citra:",
            options=UI_STATUS_CHOICES,
            index=0,
            help="Status klasifikasi provenance yang akan disematkan ke dalam metadata.",
        )
        st.info(f"Operator tercatat otomatis: **{st.session_state['user_email']}**")

    # Real-time Capacity Analysis & Capacity Guard
    if cover_file is not None:
        st.markdown("---")
        st.subheader("📊 Analisis Kapasitas Citra")

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_cover:
            tmp_cover_path = tmp_cover.name
            cover_file.seek(0)
            tmp_cover.write(cover_file.read())

        try:
            img = Image.open(tmp_cover_path)
            w, h = img.size
            img.close()

            avail_bits = calculate_capacity(w, h)
            avail_bytes = avail_bits / 8

            # Calculate required payload size dynamically (Stego-Key loaded strictly in backend)
            required_bits = compute_preview_payload_bits(
                cover_path=tmp_cover_path,
                user_email=st.session_state["user_email"],
                status=status_choice,
            )
            required_bytes = required_bits / 8
            remaining_bits = avail_bits - required_bits
            remaining_bytes = remaining_bits / 8
            usage_pct = (required_bits / avail_bits * 100) if avail_bits > 0 else 0.0

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Dimensi Citra", f"{w} × {h} px", f"{(w // 8) * (h // 8)} blok 8×8")
            m2.metric("Kapasitas Tersedia", f"{avail_bits} bits", f"{avail_bytes:.1f} bytes")
            m3.metric("Ukuran Payload Diperlukan", f"{required_bits} bits", f"{required_bytes:.1f} bytes")
            m4.metric("Kapasitas Tersisa", f"{remaining_bits} bits", f"{remaining_bytes:.1f} bytes")

            clamped_pct = min(max(usage_pct / 100.0, 0.0), 1.0)
            st.write(f"**Penggunaan Kapasitas Citra:** `{usage_pct:.1f}%`")
            st.progress(clamped_pct)

            # Capacity Guard: if required > available, abort and disable embed button
            if required_bits > avail_bits or usage_pct > 100.0:
                st.error("ERROR: Ukuran gambar terlalu kecil untuk menampung metadata ini!")
                embed_disabled = True
            else:
                embed_disabled = False

            st.markdown("---")
            if st.button("🚀 Embed Metadata", type="primary", disabled=embed_disabled):
                with st.spinner("Sedang melakukan modulasi DCT frekuensi menengah dan enkripsi..."):
                    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_out:
                        tmp_out_path = tmp_out.name

                    try:
                        # Secret key retrieved silently from backend environment
                        stego_key = get_stego_key()

                        embed(
                            cover_path=tmp_cover_path,
                            output_path=tmp_out_path,
                            user_email=st.session_state["user_email"],
                            status=status_choice,
                            stego_key=stego_key,
                            image_width=w,
                            image_height=h,
                        )

                        with open(tmp_out_path, "rb") as f_out:
                            stego_png_bytes = f_out.read()

                        st.success("🎉 Metadata Berhasil Disisipkan ke dalam Citra!")

                        # Side-by-side preview
                        prev_col1, prev_col2 = st.columns(2)
                        with prev_col1:
                            st.image(
                                Image.open(tmp_cover_path),
                                caption="Citra Cover Awal",
                                use_container_width=True,
                            )
                        with prev_col2:
                            st.image(
                                Image.open(io.BytesIO(stego_png_bytes)),
                                caption="Citra Stego Output (Lossless PNG)",
                                use_container_width=True,
                            )

                        # Download button
                        st.download_button(
                            label="⬇️ Unduh Stego PNG",
                            data=stego_png_bytes,
                            file_name=f"stego_{os.path.splitext(cover_file.name)[0]}.png",
                            mime="image/png",
                            type="primary",
                        )

                    except Exception as exc:
                        st.error(f"Gagal melakukan embedding: {exc}")
                    finally:
                        if os.path.exists(tmp_out_path):
                            try:
                                os.remove(tmp_out_path)
                            except OSError:
                                pass

        finally:
            if os.path.exists(tmp_cover_path):
                try:
                    os.remove(tmp_cover_path)
                except OSError:
                    pass


# ===========================================================================
# TAB 2: Extract & Verify
# ===========================================================================
with tab2:
    st.header("🔍 Ekstraksi & Verifikasi Metadata Provenance")
    st.markdown("Ekstraksi bitstream dari koefisien DCT, verifikasi integritas SHA-256, dan evaluasi izin akses RBAC.")

    stego_file = st.file_uploader(
        "Unggah Citra Stego (.png) yang Akan Diperiksa:",
        type=["png"],
        key="tab2_stego_uploader",
    )

    admin_secret_key_input = ""
    if stego_file is not None:
        st.image(Image.open(stego_file), caption=f"File: {stego_file.name}", width=320)

        # Conditional Admin Secret Key prompt for admin@gmail.com
        if st.session_state["is_admin"]:
            st.markdown("---")
            admin_secret_key_input = st.text_input(
                "Masukkan Admin Secret Key:",
                type="password",
                help="Masukkan ADMIN_KEY dari sistem (.env) untuk membuka hak akses Admin penuh.",
                key="admin_secret_key_field",
            )

        if st.button("🔓 Extract & Verify Metadata", type="primary"):
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_extract:
                tmp_extract_path = tmp_extract.name
                stego_file.seek(0)
                tmp_extract.write(stego_file.read())

            try:
                # 1. Inspect and extract raw DCT payload
                try:
                    header_bytes, pub_bytes, cipher_bytes, sha256_bytes = extract_payload(tmp_extract_path)
                except ValueError:
                    st.error("🚨 Tidak ditemukan metadata steganografi yang valid pada gambar ini.")
                    st.stop()

                # Calculate extracted payload bit size & capacity statistics
                extracted_bits = compute_payload_bits(header_bytes, pub_bytes, cipher_bytes, sha256_bytes)
                img = Image.open(tmp_extract_path)
                w, h = img.size
                img.close()
                avail_bits = calculate_capacity(w, h)
                used_pct = (extracted_bits / avail_bits * 100) if avail_bits > 0 else 0.0

                st.markdown("### 📊 Statistik Kapasitas Payload")
                ec1, ec2, ec3 = st.columns(3)
                ec1.metric("Ukuran Payload Terekstraksi", f"{extracted_bits} bits", f"{extracted_bits / 8:.2f} bytes")
                ec2.metric("Kapasitas Terpakai", f"{used_pct:.1f}%")
                ec3.metric("Total Kapasitas Citra", f"{avail_bits} bits", f"{avail_bits / 8:.2f} bytes")
                st.markdown("---")

                # 2. SHA-256 Integrity Verification
                integrity_ok = verify_sha256(cipher_bytes, sha256_bytes)
                st.markdown("### 🛡️ Status Integritas Citra (SHA-256)")
                if integrity_ok:
                    st.success("✅ STATUS INTEGRITAS: VALID (SHA-256 Match) — Metadata otentik dan belum dimodifikasi.")
                else:
                    st.error("❌ STATUS INTEGRITAS: GAGAL / TERKONTAMINASI (SHA-256 Mismatch) — Citra telah dimanipulasi atau rusak!")
                    st.stop()

                # 3. Public Metadata (always accessible)
                try:
                    pub_data = json.loads(pub_bytes.decode("utf-8"))
                except json.JSONDecodeError:
                    pub_data = {}

                st.markdown("### 📋 Public Metadata")
                pb1, pb2 = st.columns(2)
                pb1.info(f"**Status Terakhir:** {pub_data.get('current_status', 'N/A')}")
                pb2.info(f"**Terakhir Diubah Oleh:** {pub_data.get('last_modified_by', 'N/A')}")

                # 4. Decrypt Private Metadata (using backend STEGO_SECRET_KEY)
                stego_key = get_stego_key()
                try:
                    header_dict = json.loads(header_bytes.decode("utf-8"))
                    iv = bytes.fromhex(header_dict["iv"])
                    private_json = aes_decrypt(cipher_bytes, iv, stego_key)
                    private_data = json.loads(private_json)
                except Exception as dec_exc:
                    st.error(f"Gagal melakukan dekripsi private metadata: {dec_exc}")
                    st.stop()

                creator_credential = private_data.get("creator_credential", {})
                credential_history = private_data.get("credential_history", [])
                creator_email = creator_credential.get("creator_email", "")

                # 5. Role-Based Access Control (RBAC)
                env_admin_key = get_admin_key()
                role = determine_role(
                    user_email=st.session_state["user_email"],
                    admin_key_input=admin_secret_key_input,
                    creator_email=creator_email,
                    env_admin_key=env_admin_key,
                )

                st.markdown("### 👤 Hasil Otorisasi Akses (RBAC)")
                if is_full_access(role):
                    st.success(f"🔑 Hak Akses Terverifikasi: **{role_label(role)}**")

                    st.markdown("#### 📜 Kredensial Pembuat Citra (Creator Credential)")
                    cr1, cr2 = st.columns(2)
                    cr1.text_input("Pembuat (Creator Email)", value=creator_credential.get("creator_email", "N/A"), disabled=True)
                    cr2.text_input("Dibuat Pada (Creation Timestamp)", value=format_timestamp(creator_credential.get("created_at", "")), disabled=True)

                    st.markdown("#### ⏳ Riwayat Kredensial & Provenance (Credential History)")
                    if credential_history:
                        history_rows = []
                        for idx, entry in enumerate(credential_history, start=1):
                            history_rows.append({
                                "No": idx,
                                "Aksi / Status": entry.get("action", ""),
                                "Pengguna / Operator": entry.get("user_email", ""),
                                "Waktu (UTC)": format_timestamp(entry.get("timestamp", "")),
                            })
                        df_history = pd.DataFrame(history_rows)
                        st.dataframe(df_history, use_container_width=True, hide_index=True)
                    else:
                        st.write("Tidak ada entri riwayat tambahan.")
                else:
                    st.warning("🔒 AKSES TERBATAS: Detail private metadata hanya dapat dilihat oleh Pemilik Utama Gambar atau Admin.")
                    st.info("Sebagai Guest / Editor, Anda hanya diperkenankan melihat Status Integritas dan Public Metadata di atas.")

            finally:
                if os.path.exists(tmp_extract_path):
                    try:
                        os.remove(tmp_extract_path)
                    except OSError:
                        pass


# ===========================================================================
# TAB 3: Capacity Inspector
# ===========================================================================
with tab3:
    st.header("📊 Capacity Inspector (Cek Kapasitas Citra)")
    st.markdown("Periksa dimensi, kapasitas bit maksimum, serta keberadaan payload steganografi pada gambar.")

    inspect_file = st.file_uploader(
        "Pilih Gambar untuk Diperiksa Kapasitasnya:",
        type=["png", "jpg", "jpeg"],
        key="tab3_inspect_uploader",
    )

    if inspect_file is not None:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_insp:
            tmp_insp_path = tmp_insp.name
            inspect_file.seek(0)
            tmp_insp.write(inspect_file.read())

        try:
            insp_img = Image.open(tmp_insp_path)
            w, h = insp_img.size
            insp_img.close()

            avail_bits = calculate_capacity(w, h)
            avail_bytes = avail_bits / 8
            total_blocks = (w // BLOCK_SIZE) * (h // BLOCK_SIZE)

            # Check if image contains an existing embedded payload
            embedded_bits = get_embedded_payload_bits(tmp_insp_path)
            embedded_bytes = embedded_bits / 8

            c_img, c_stat = st.columns([1, 2], gap="medium")
            with c_img:
                st.image(Image.open(tmp_insp_path), caption=inspect_file.name, use_container_width=True)

            with c_stat:
                st.subheader("Rincian Kapasitas DCT")
                i1, i2 = st.columns(2)
                i1.metric("Dimensi Citra", f"{w} × {h} px")
                i2.metric("Total Blok 8×8", f"{total_blocks:,} blok")

                i3, i4 = st.columns(2)
                i3.metric("Kapasitas Maksimal (Bits)", f"{avail_bits:,} bits")
                i4.metric("Kapasitas Maksimal (Bytes)", f"{avail_bytes:,.1f} bytes")

                st.markdown("---")
                if embedded_bits > 0:
                    usage_pct = (embedded_bits / avail_bits * 100) if avail_bits > 0 else 0.0
                    e1, e2 = st.columns(2)
                    e1.metric("Payload Terdeteksi", "Ya (Detected)", delta="Ada Metadata")
                    e2.metric("Ukuran Payload", f"{embedded_bits} bits", f"{embedded_bytes:.1f} bytes")

                    st.write(f"**Penggunaan Kapasitas Terpakai:** `{usage_pct:.1f}%`")
                    st.progress(min(max(usage_pct / 100.0, 0.0), 1.0))
                else:
                    st.metric("Payload Terdeteksi", "Tidak Ada", delta="0% Terpakai", delta_color="off")
                    st.info("ℹ️ No embedded metadata detected. Image is 100% available.")
                    st.progress(0.0)

        finally:
            if os.path.exists(tmp_insp_path):
                try:
                    os.remove(tmp_insp_path)
                except OSError:
                    pass
