import ctypes
import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from pathlib import Path
import base64
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# -------------------------------------------------------------
# ADMIN CHECK
# -------------------------------------------------------------

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# -------------------------------------------------------------
# PATH TO COMPILED LAUNCHER TEMPLATE
# -------------------------------------------------------------
# IMPORTANT:
# This must point to your compiled launcher_template.exe
LAUNCHER_TEMPLATE = Path(__file__).parent / "launcher_template.exe"


# -------------------------------------------------------------
# MAIN LOCKER CLASS
# -------------------------------------------------------------

class ExeLocker:
    def __init__(self, root):
        self.root = root
        self.root.title("File Locker")
        self.root.geometry("500x300")
        self.root.resizable(False, False)

        self.build_ui()

    # UI -------------------------------------------------------

    def build_ui(self):
        main = tk.Frame(self.root, padx=20, pady=20)
        main.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            main,
            text="File Locker",
            font=("Arial", 18, "bold")
        ).pack(pady=(0, 20))

        tk.Label(
            main,
            text="Encrypt or decrypt files with password protection",
            font=("Arial", 10),
            fg="gray"
        ).pack(pady=(0, 30))

        tk.Button(
            main,
            text="🔒 Lock File",
            font=("Arial", 12),
            bg="#4CAF50",
            fg="white",
            padx=20,
            pady=10,
            command=self.lock_file,
            cursor="hand2"
        ).pack(pady=10)

        tk.Button(
            main,
            text="🔓 Unlock File",
            font=("Arial", 12),
            bg="#2196F3",
            fg="white",
            padx=20,
            pady=10,
            command=self.unlock_file,
            cursor="hand2"
        ).pack(pady=10)

        self.status_label = tk.Label(
            main,
            text="",
            font=("Arial", 9),
            fg="green"
        )
        self.status_label.pack(pady=20)

    # ----------------------------------------------------------
    # KEY DERIVATION
    # ----------------------------------------------------------

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # ----------------------------------------------------------
    # LOCK FILE
    # ----------------------------------------------------------

    def lock_file(self):
        fpath = filedialog.askopenfilename(
            title="Select file to lock",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if not fpath:
            return

        fpath = Path(fpath)
        if not fpath.exists():
            messagebox.showerror("Error", "File does not exist!")
            return

        pw = simpledialog.askstring("Password", "Enter password:", show='*')
        if not pw:
            return

        pw2 = simpledialog.askstring("Confirm", "Confirm password:", show='*')
        if pw != pw2:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        try:
            raw = fpath.read_bytes()

            salt = os.urandom(16)
            key = self.derive_key(pw, salt)
            fernet = Fernet(key)

            encrypted = fernet.encrypt(raw)
            locked_path = fpath.with_suffix(fpath.suffix + ".locked")

            # Write encrypted data
            locked_path.write_bytes(salt + encrypted)

            # Delete original EXE
            fpath.unlink()

            # ---------------------------------------------------------
            # COPY LAUNCHER TEMPLATE AND RENAME TO ORIGINAL EXE NAME
            # ---------------------------------------------------------
            launcher_destination = fpath  # exact original path

            shutil.copy(LAUNCHER_TEMPLATE, launcher_destination)

            self.status_label.config(text="✓ Locked successfully", fg="green")
            messagebox.showinfo(
                "Success",
                f"Locked file created:\n{locked_path}\n"
                f"Launcher installed:\n{launcher_destination}"
            )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to lock file:\n{e}")
            self.status_label.config(text="✗ Lock failed", fg="red")

    # ----------------------------------------------------------
    # UNLOCK FILE
    # ----------------------------------------------------------

    def unlock_file(self):
        fpath = filedialog.askopenfilename(
            title="Select .locked file",
            filetypes=[("Locked files", "*.locked"), ("All files", "*.*")]
        )
        if not fpath:
            return

        fpath = Path(fpath)
        if not fpath.exists():
            messagebox.showerror("Error", "File does not exist!")
            return

        pw = simpledialog.askstring("Password", "Enter password:", show='*')
        if not pw:
            return

        try:
            data = fpath.read_bytes()
            salt = data[:16]
            encrypted = data[16:]

            key = self.derive_key(pw, salt)
            fernet = Fernet(key)

            try:
                decrypted = fernet.decrypt(encrypted)
            except Exception:
                messagebox.showerror("Error", "Incorrect password!")
                self.status_label.config(text="✗ Incorrect password", fg="red")
                return

            original_path = fpath.with_suffix("")  # remove .locked

            original_path.write_bytes(decrypted)
            fpath.unlink()

            self.status_label.config(text="✓ Unlocked successfully", fg="green")
            messagebox.showinfo(
                "Success",
                f"Unlocked file:\n{original_path}"
            )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock file:\n{e}")
            self.status_label.config(text="✗ Unlock failed", fg="red")


# -------------------------------------------------------------
# MAIN
# -------------------------------------------------------------

def main():
    root = tk.Tk()
    app = ExeLocker(root)
    root.mainloop()


if __name__ == "__main__":
    if is_admin():
        main()
    else:
        # Request elevation
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            " ".join(sys.argv),
            None,
            1
        )
