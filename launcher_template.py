#!/usr/bin/env python3
import os
import sys
import tempfile
import subprocess
import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from pathlib import Path


def derive_key(password: str, salt: bytes) -> bytes:
    """Use the SAME PBKDF2 setup as the locker."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def main():
    root = tk.Tk()
    root.withdraw()

    launcher_path = Path(sys.argv[0])
    locked_path = launcher_path.with_suffix(launcher_path.suffix + ".locked")

    if not locked_path.exists():
        messagebox.showerror("Error",
                             f"Locked file not found:\n{locked_path.name}\n"
                             f"This program is locked and cannot run.")
        return

    password = simpledialog.askstring(
        "Unlock Program",
        f"Enter password to run {launcher_path.name}:",
        show="*"
    )
    if password is None:
        return

    try:
        data = locked_path.read_bytes()
        salt = data[:16]
        encrypted = data[16:]

        key = derive_key(password, salt)
        fernet = Fernet(key)

        try:
            decrypted = fernet.decrypt(encrypted)
        except Exception:
            messagebox.showerror("Error", "Incorrect password!")
            return

        temp_exe_path = Path(tempfile.gettempdir()) / (launcher_path.stem + "_run.exe")
        temp_exe_path.write_bytes(decrypted)

        proc = subprocess.Popen([str(temp_exe_path)])
        proc.wait()

        try:
            temp_exe_path.unlink()
        except PermissionError:
            pass

    except Exception as e:
        messagebox.showerror("Error", f"Unable to launch program:\n{e}")


if __name__ == "__main__":
    main()
