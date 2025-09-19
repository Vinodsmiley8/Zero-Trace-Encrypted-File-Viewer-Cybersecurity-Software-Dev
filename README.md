# Zero-Trace Encrypted File Viewer (ZTEFV)

**Category:** Cybersecurity + Software Dev  
**Author:** Prepared for GitHub user `vinodsmiley8`

## Overview
ZTEFV is a small Python project demonstrating a "zero-trace" encrypted file viewer: encrypted files are decrypted strictly **in memory** and displayed in a GUI without writing plaintext to disk.

**Important:** This is a demonstration/educational project. Review the cryptography usage and threat model before using in production.

## Features
- AES-GCM authenticated encryption (password-derived key)
- Command-line encryptor (`encrypt.py`) to create `.ztef` encrypted files
- Tkinter GUI viewer (`viewer.py`) that loads and decrypts files only in memory
- No plaintext written to disk by the viewer (unless user explicitly exports)

## Requirements
- Python 3.8+
- `cryptography` library (`pip install -r requirements.txt`)

## Quickstart
1. create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # on Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. encrypt a file:
   ```bash
   python -m ztefv.encrypt --in README.md --out README.ztef
   ```
   You'll be prompted for a passphrase.
3. run the viewer:
   ```bash
   python -m ztefv.viewer README.ztef
   ```
   Enter the passphrase and the file will be decrypted in memory and displayed.

## File format (simple)
`ZTEF` magic (4 bytes) | version (1 byte) | salt (16 bytes) | nonce (12 bytes) | ciphertext...

## Notes & Security
- Uses PBKDF2-HMAC-SHA256 with 200,000 iterations to derive an AES-256 key from a passphrase.
- AES-GCM provides confidentiality + authenticity.
- This project is for educational use. Consider using audited libraries & follow secure key management for production.

## License
MIT
