# Hybrid Encryption Dashboard (AES + RSA)

This project is an interactive dashboard built with **Streamlit** that demonstrates **proper hybrid encryption**:

- **AES-256-GCM** encrypts the actual message (fast, secure, authenticated).
- **RSA-OAEP (SHA-256)** encrypts the AES key (key wrapping).
- The encrypted bundle is output in JSON format for easy sharing.

You can generate keys, encrypt text, and decrypt it back — all without using any database.  
Everything runs in memory and is handled through the dashboard UI.

---

## Features

- Generate a fresh RSA key pair (2048 bits by default).
- Generate a random AES-256 key for message encryption.
- Encrypt plaintext into a JSON bundle containing:
  - Wrapped AES key (`ek`)
  - Nonce (`nonce`)
  - Ciphertext + tag (`ct`)
  - Algorithm metadata (`algs`)
- Decrypt using:
  - RSA private key (unwrap AES key, then decrypt message), or
  - AES key directly (skip RSA, for demo/testing).
- Optional **AAD (Associated Authenticated Data)** to bind extra context.
- No database or persistence — copy/paste and share as you like.

---

## Installation

Clone the repo:

```bash
git clone https://github.com/suyog12/hybridEncryption.git
cd hybrid-encryption-dashboard
```

---

Install dependencies:

```bash
pip install -r requirements.txt
```

---

Run the App:

```bash
streamlit run app.py
```

---

## Usage

- Generate Keys
  - Click "Generate RSA keypair" and/or "Generate AES key".

- Encrypt
  - Paste or type text in the plaintext box.
  - Choose to use the session public key or paste a custom public key.
  - Click "Encrypt".
  - Copy the JSON bundle output.

- Decrypt
  - Paste the JSON bundle.
  - Either:
    - Provide the RSA private key (to unwrap the AES key), or
    - Provide the AES key directly (for testing).
    - Click "Decrypt".
    - The original plaintext will be shown.

---

## JSON Bundle Format

Example output:
```json
{
  "algs": {
    "sym": "aes_gcm_256",
    "wrap": "rsa_oaep_sha256"
  },
  "rsa_pub_fpr": "d3a1b2c9e8f4a1d2",
  "ek": "Base64(RSA-wrapped AES key)",
  "nonce": "Base64(random 12-byte nonce)",
  "ct": "Base64(AES-GCM ciphertext+tag)",
  "aad_present": false
}
```

---

## Security Notes

- Demo only: Do not use this as-is for production secrets.
- Always protect your RSA private key (never share it).
- AES-GCM provides integrity checks; for sender authenticity, add digital signatures (e.g., RSA-PSS).
- For real deployments, always serve over HTTPS.
