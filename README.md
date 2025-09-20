# 🔐 Hybrid Encryption Dashboard (AES + RSA)

This project is an interactive dashboard built with **Streamlit** that demonstrates **proper hybrid encryption**:

- **AES-256-GCM** encrypts the actual message (fast, secure, authenticated).
- **RSA-OAEP (SHA-256)** encrypts the AES key (key wrapping).
- The encrypted bundle is output in JSON format for easy sharing.

You can generate keys, encrypt text, and decrypt it back — all without using any database.  
Everything runs in memory and is handled through the dashboard UI.

---

## ✨ Features

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

## 🛠️ Installation

Clone the repo:

```bash
git clone https://github.com/<your-username>/hybrid-encryption-dashboard.git
cd hybrid-encryption-dashboard
