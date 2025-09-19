"""Zero-Trace Encrypted File Viewer (Tkinter GUI)

Usage:
    python -m ztefv.viewer path/to/file.ztef
"""

import sys, getpass
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext
except Exception as e:
    print('Tkinter is required for the GUI.')
    raise

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'ZTEF'

def derive_key(password: bytes, salt: bytes, iterations=200_000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password)

def decrypt_bytes(data: bytes, password: bytes) -> bytes:
    if not data.startswith(MAGIC):
        raise ValueError('Not a ZTEF file (magic mismatch)')
    version = data[4]
    # simple format: magic(4) | version(1) | salt(16) | nonce(12) | ciphertext...
    salt = data[5:21]
    nonce = data[21:33]
    ct = data[33:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

class ViewerApp(tk.Tk):
    def __init__(self, initial_file=None):
        super().__init__()
        self.title('Zero-Trace Encrypted File Viewer')
        self.geometry('800x600')
        self._create_widgets()
        if initial_file:
            self.open_file(initial_file)

    def _create_widgets(self):
        frm = tk.Frame(self)
        frm.pack(fill='x', padx=8, pady=6)
        tk.Button(frm, text='Open .ztef', command=self._open_dialog).pack(side='left')
        tk.Button(frm, text='Exit', command=self.destroy).pack(side='right')
        self.text = scrolledtext.ScrolledText(self, wrap='none')
        self.text.pack(fill='both', expand=True, padx=8, pady=6)
        self.text.insert('1.0', 'Open an encrypted .ztef file to view its contents here (decrypted only in memory).')
        self.text.configure(state='disabled')

    def _open_dialog(self):
        path = filedialog.askopenfilename(filetypes=[('ZTEF files', '*.ztef'), ('All files','*.*')])
        if path:
            self.open_file(path)

    def open_file(self, path):
        pwd = getpass.getpass(f'Passphrase for {path}: ').encode('utf-8')
        try:
            with open(path, 'rb') as f:
                data = f.read()
            plaintext = decrypt_bytes(data, pwd)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to decrypt or open file:\n{e}')
            return
        # display (try text, otherwise show hex)
        try:
            text = plaintext.decode('utf-8')
            is_text = True
        except:
            text = plaintext.hex()
            is_text = False
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        header = f'-- Decrypted in memory ({"text" if is_text else "binary-hex"}) --\n'
        self.text.insert('1.0', header + text)
        self.text.configure(state='disabled')

def main():
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    app = ViewerApp(initial)
    app.mainloop()

if __name__ == '__main__':
    main()
