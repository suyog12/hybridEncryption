import base64, hashlib, json, os, textwrap
import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ---------- Helpers ----------
def b64e(b: bytes) -> str: return base64.b64encode(b).decode("utf-8")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("utf-8"))

def rsa_gen(bits=2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem

def rsa_load_pub(pem: bytes):
    return serialization.load_pem_public_key(pem)

def rsa_load_priv(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)

def pubkey_fingerprint_sha256(pub_pem: bytes) -> str:
    der = serialization.load_pem_public_key(pub_pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()[:16]

def aes_key_gen() -> bytes:
    return AESGCM.generate_key(bit_length=256)  # 32 bytes

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None):
    nonce = os.urandom(12)
    gcm = AESGCM(key)
    ct = gcm.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes | None = None):
    gcm = AESGCM(key)
    return gcm.decrypt(nonce, ct, aad)

def rsa_wrap_key(pub, aes_key: bytes) -> bytes:
    return pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def rsa_unwrap_key(priv, wrapped: bytes) -> bytes:
    return priv.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

# ---------- UI ----------
st.set_page_config(page_title="Proper Hybrid Encryption (AES-GCM + RSA-OAEP)", layout="centered")
st.title("Hybrid Encryption: AES-GCM (data) + RSA-OAEP (key wrap)")

st.markdown(
    "- **AES-256-GCM** encrypts your text (confidentiality + integrity)\n"
    "- **RSA-OAEP (SHA-256)** wraps the AES key\n"
    "- Outputs a JSON bundle\n"
    "- No database. Everything is in memory/paste."
)

st.divider()
st.header("1) Keys")

c1, c2 = st.columns(2)
with c1:
    if st.button("Generate RSA keypair (2048)", key="btn_gen_rsa"):
        priv_pem, pub_pem = rsa_gen(2048)
        st.session_state["priv_pem"] = priv_pem
        st.session_state["pub_pem"]  = pub_pem
        st.success("RSA keypair generated (session only).")
    if "pub_pem" in st.session_state:
        st.text_area(
            "RSA Public Key (PEM)",
            st.session_state["pub_pem"].decode(),
            height=160,
            key="view_pub_pem",
        )
with c2:
    if st.button("Generate AES-256 key", key="btn_gen_aes"):
        st.session_state["aes_key"] = aes_key_gen()
        st.success("AES key generated (session only).")
    if "aes_key" in st.session_state:
        st.text_input(
            "AES-256 key (Base64)",
            b64e(st.session_state["aes_key"]),
            key="view_aes_key_b64",
        )

st.divider()
st.header("2) Encrypt")

plaintext = st.text_area(
    "Plaintext to encrypt",
    height=160,
    placeholder="Type or paste any text/paragraph here...",
    key="ta_plaintext",
)

use_session_pub = st.checkbox("Use the RSA public key above (session)", value=True, key="cb_use_session_pub")
pub_pem_in = st.text_area(
    "Or paste RSA Public Key (PEM) here",
    height=120,
    placeholder="-----BEGIN PUBLIC KEY----- ...",
    key="ta_pub_pem_paste",
)

use_aad = st.checkbox("Add AAD (associated data) for extra context binding", value=False, key="cb_use_aad")
aad_in = st.text_input(
    "AAD (optional; must be provided again to decrypt)",
    value="",
    key="ti_aad_enc",
) if use_aad else ""

if st.button("Encrypt (AES-GCM data + RSA-OAEP wrap key)", key="btn_encrypt"):
    try:
        # Resolve RSA public key
        if use_session_pub and "pub_pem" in st.session_state:
            pub_pem = st.session_state["pub_pem"]
        else:
            if not pub_pem_in.strip():
                st.error("Provide a RSA public key PEM.")
                st.stop()
            pub_pem = pub_pem_in.encode()
        pub = rsa_load_pub(pub_pem)

        # Resolve / generate AES key
        aes_key = st.session_state.get("aes_key") or aes_key_gen()
        st.session_state["aes_key"] = aes_key

        # AES-GCM encrypt
        aad_bytes = aad_in.encode() if use_aad and aad_in else None
        nonce, ct = aes_gcm_encrypt(aes_key, plaintext.encode("utf-8"), aad=aad_bytes)

        # RSA-OAEP wrap the AES key
        ek = rsa_wrap_key(pub, aes_key)

        bundle = {
            "algs": {"sym": "aes_gcm_256", "wrap": "rsa_oaep_sha256"},
            "rsa_pub_fpr": pubkey_fingerprint_sha256(pub_pem),
            "ek": b64e(ek),
            "nonce": b64e(nonce),
            "ct": b64e(ct),
            "aad_present": bool(aad_bytes),
        }
        st.session_state["last_bundle"] = json.dumps(bundle, indent=2)
        st.success("Encrypted with AES-GCM; AES key wrapped with RSA-OAEP.")
        st.code(st.session_state["last_bundle"], language="json")

        if "priv_pem" in st.session_state:
            st.info("Your RSA PRIVATE key (keep secret!)")
            st.text_area(
                "RSA Private Key (PEM)",
                st.session_state["priv_pem"].decode(),
                height=160,
                key="view_priv_pem",
            )

    except Exception as e:
        st.exception(e)

st.divider()
st.header("3) Decrypt")

method = st.radio(
    "Choose method",
    ["RSA private key (unwrap AES key)", "Direct AES key (skip RSA)"],
    key="radio_method",
)

if method == "RSA private key (unwrap AES key)":
    priv_pem_in = st.text_area(
        "RSA Private Key (PEM)",
        value=(st.session_state.get("priv_pem", b"").decode()
               if st.session_state.get("priv_pem") else ""),
        height=160,
        key="ta_priv_pem_input",
    )
    bundle_in = st.text_area(
        "Paste JSON bundle",
        value=st.session_state.get("last_bundle", ""),
        height=220,
        key="ta_bundle_rsa",
    )
    aad_in2 = st.text_input(
        "AAD (required if it was set during encryption)",
        value="",
        key="ti_aad_dec_rsa",
    )

    if st.button("Decrypt (RSA→AES→Plaintext)", key="btn_decrypt_rsa"):
        try:
            if not priv_pem_in.strip(): st.error("Private key required."); st.stop()
            if not bundle_in.strip():   st.error("Bundle required.");     st.stop()

            priv = rsa_load_priv(priv_pem_in.encode())
            bundle = json.loads(bundle_in)

            ek    = b64d(bundle["ek"])
            nonce = b64d(bundle["nonce"])
            ct    = b64d(bundle["ct"])
            aad_b = aad_in2.encode() if bundle.get("aad_present") else None

            aes_key = rsa_unwrap_key(priv, ek)
            pt = aes_gcm_decrypt(aes_key, nonce, ct, aad=aad_b)
            st.success("Decryption OK")
            st.text_area("Plaintext", pt.decode("utf-8"), height=160, key="ta_plaintext_out_rsa")
        except Exception as e:
            st.exception(e)

else:
    aes_key_b64 = st.text_input(
        "AES key (Base64)",
        value=b64e(st.session_state["aes_key"]) if st.session_state.get("aes_key") else "",
        key="ti_aes_dec",
    )
    bundle_in2 = st.text_area(
        "Paste JSON bundle",
        value=st.session_state.get("last_bundle", ""),
        height=220,
        key="ta_bundle_aes",
    )
    aad_in3 = st.text_input(
        "AAD (required if it was set during encryption)",
        value="",
        key="ti_aad_dec_aes",
    )

    if st.button("Decrypt (AES only)", key="btn_decrypt_aes"):
        try:
            if not aes_key_b64.strip(): st.error("AES key required."); st.stop()
            if not bundle_in2.strip():  st.error("Bundle required.");  st.stop()

            aes_key = b64d(aes_key_b64)
            bundle = json.loads(bundle_in2)

            nonce = b64d(bundle["nonce"])
            ct    = b64d(bundle["ct"])
            aad_b = aad_in3.encode() if bundle.get("aad_present") else None

            pt = aes_gcm_decrypt(aes_key, nonce, ct, aad=aad_b)
            st.success("Decryption OK")
            st.text_area("Plaintext", pt.decode("utf-8"), height=160, key="ta_plaintext_out_aes")
        except Exception as e:
            st.exception(e)

st.divider()
st.caption(textwrap.dedent("""
Security notes:
- Demo only: protect the private key, use HTTPS, consider passphrase-encrypted PKCS#8 if persisting.
- AES-GCM authenticates ciphertext; add **signatures (RSA-PSS)** if you need **sender** auth.
- The JSON bundle is self-describing for storage/transmission.
"""))