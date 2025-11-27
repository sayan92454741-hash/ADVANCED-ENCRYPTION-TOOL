import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk, messagebox

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# -------- Key Derivation -------- #
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=250000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# -------- Encryption -------- #
def encrypt_file(in_path, out_path, password, progress_callback):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    size = os.path.getsize(in_path)
    done = 0

    with open(in_path, "rb") as f_in, open(out_path, "wb") as f_out:
        f_out.write(b"AESGCM")
        f_out.write(b"\x01")
        f_out.write(salt)
        f_out.write(nonce)

        while chunk := f_in.read(65536):
            done += len(chunk)
            f_out.write(encryptor.update(chunk))
            progress_callback(done / size * 100)

        encryptor.finalize()
        f_out.write(encryptor.tag)

    progress_callback(100)


# -------- Decryption -------- #
def decrypt_file(in_path, out_path, password, progress_callback):
    with open(in_path, "rb") as f_in:
        if f_in.read(6) != b"AESGCM":
            raise ValueError("Invalid encrypted file")

        version = f_in.read(1)
        if version != b"\x01":
            raise ValueError("Unsupported version")

        salt = f_in.read(16)
        nonce = f_in.read(12)

        key = derive_key(password, salt)

        file_size = os.path.getsize(in_path)
        remaining = file_size - (6 + 1 + 16 + 12 + 16)

        f_in.seek(file_size - 16)
        tag = f_in.read(16)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        f_in.seek(6 + 1 + 16 + 12)
        done = 0

        with open(out_path, "wb") as f_out:
            while remaining > 0:
                chunk = f_in.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                done += len(chunk)

                f_out.write(decryptor.update(chunk))
                progress_callback(done / (file_size - 51) * 100)

            decryptor.finalize()

    progress_callback(100)


# ============================================
#                 GUI APP
# ============================================
class EncryptorGUI:
    def __init__(self, root):
        self.root = root
        root.title("Advanced AES-256 Encryption Tool")
        root.geometry("600x450")

        # ----- Input ----- #
        tk.Label(root, text="Input File").pack()
        self.infile = tk.Entry(root, width=60)
        self.infile.pack()
        tk.Button(root, text="Browse", command=self.browse_in).pack()

        # ----- Output ----- #
        tk.Label(root, text="Output File").pack()
        self.outfile = tk.Entry(root, width=60)
        self.outfile.pack()
        tk.Button(root, text="Browse", command=self.browse_out).pack()

        # ----- Password ----- #
        tk.Label(root, text="Password").pack()
        self.password = tk.Entry(root, show="*", width=40)
        self.password.pack()

        # ----- Mode ----- #
        self.mode = tk.StringVar(value="encrypt")
        tk.Radiobutton(root, text="Encrypt", variable=self.mode, value="encrypt").pack()
        tk.Radiobutton(root, text="Decrypt", variable=self.mode, value="decrypt").pack()

        # ----- Progress Bar ----- #
        tk.Label(root, text="Progress").pack()
        self.pbar = ttk.Progressbar(root, length=500)
        self.pbar.pack(pady=5)

        # ----- Log ----- #
        self.log = tk.Text(root, height=8)
        self.log.pack(fill="both")

        # ----- Start Button ----- #
        tk.Button(root, text="Start", command=self.start).pack(pady=10)

    # ---------------- Helpers ---------------- #
    def browse_in(self):
        path = filedialog.askopenfilename()
        if path:
            self.infile.delete(0, tk.END)
            self.infile.insert(0, path)

    def browse_out(self):
        path = filedialog.asksaveasfilename()
        if path:
            self.outfile.delete(0, tk.END)
            self.outfile.insert(0, path)

    # ----- Thread-Safe Logging ----- #
    def log_msg(self, msg):
        self.root.after(0, self._append_log, msg)

    def _append_log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    # ----- Thread-Safe Progress Bar ----- #
    def update_progress(self, value):
        self.root.after(0, self._set_progress, value)

    def _set_progress(self, value):
        self.pbar["value"] = value

    # ----------------------------------------- #
    #                 Worker
    # ----------------------------------------- #
    def start(self):
        in_path = self.infile.get().strip()
        out_path = self.outfile.get().strip()
        pwd = self.password.get()

        if not in_path or not out_path or not pwd:
            messagebox.showerror("Error", "Missing input fields")
            return

        self.log_msg(f"Starting {self.mode.get()}...")

        thread = threading.Thread(
            target=self.worker,
            args=(in_path, out_path, pwd),
            daemon=True
        )
        thread.start()

    def worker(self, in_path, out_path, pwd):
        try:
            if self.mode.get() == "encrypt":
                encrypt_file(in_path, out_path, pwd, self.update_progress)
                self.log_msg("Encryption completed.")
            else:
                decrypt_file(in_path, out_path, pwd, self.update_progress)
                self.log_msg("Decryption completed.")
        except Exception as e:
            self.log_msg(f"Error: {e}")


# ============================================
#                  RUN APP
# ============================================
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptorGUI(root)
    root.mainloop()
