"""Simple encryptor for ZTEF files.

Usage:
    python -m ztefv.encrypt --in path/to/file --out path/to/file.ztef
"""
import argparse, getpass, os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

MAGIC = b'ZTEF'
VERSION = b'\x01'

def derive_key(password: bytes, salt: bytes, iterations=200_000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password)

def encrypt_file(in_path: str, out_path: str, password: bytes):
    with open(in_path, 'rb') as f:
        plaintext = f.read()
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    with open(out_path, 'wb') as f:
        f.write(MAGIC + VERSION + salt + nonce + ct)
    print(f"Encrypted to {out_path}")

def main():
    parser = argparse.ArgumentParser(description='Encrypt a file to ZTEF format')
    parser.add_argument('--in', dest='infile', required=True, help='Input file path')
    parser.add_argument('--out', dest='outfile', required=True, help='Output .ztef file path')
    args = parser.parse_args()
    pwd = getpass.getpass('Passphrase: ').encode('utf-8')
    encrypt_file(args.infile, args.outfile, pwd)

if __name__ == '__main__':
    main()
