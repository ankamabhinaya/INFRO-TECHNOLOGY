import os
import base64
import tkinter as tk
from tkinterdnd2 import DND_FILES, TkinterDnD
from tkinter import filedialog, messagebox, simpledialog
import hashlib
from cryptography.fernet import Fernet

# Generate a key from a password
def generate_key_from_password(password):
    """Converts a password into a 32-byte encryption key."""
    key = hashlib.sha256(password.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

# Function to encrypt a file with a password
def encrypt_file(file_path):
    if not file_path:
        return

    password = simpledialog.askstring("Password", "Enter a password for encryption:", show="*")
    if not password:
        messagebox.showwarning("Warning", "Password is required for encryption!")
        return

    fernet = generate_key_from_password(password)

    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as file:
        file.write(encrypted_data)

    messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {encrypted_file_path}")

# Function to decrypt a file with a password
def decrypt_file(file_path):
    if not file_path:
        return

    if not file_path.endswith(".enc"):
        messagebox.showerror("Error", "Please select a valid encrypted file (.enc)")
        return

    password = simpledialog.askstring("Password", "Enter the decryption password:", show="*")
    if not password:
        messagebox.showwarning("Warning", "Password is required for decryption!")
        return

    fernet = generate_key_from_password(password)

    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        decrypted_file_path = file_path.replace(".enc", "")

        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {decrypted_file_path}")

    except Exception:
        messagebox.showerror("Error", "Decryption failed! Incorrect password or corrupted file.")

# Drag and Drop Functionality
def drop(event):
    file_path = event.data.strip("{}")  # Extract the correct file path
    if file_path.endswith(".enc"):
        decrypt_file(file_path)
    else:
        encrypt_file(file_path)

# GUI Setup
root = TkinterDnD.Tk()  # Use TkinterDnD for drag-and-drop support
root.title("Secure File Encryption & Decryption")
root.geometry("400x300")
root.resizable(False, False)

# Labels & Buttons
label = tk.Label(root, text="Drag & Drop Files Here", font=("Arial", 14, "bold"), fg="black", bg="lightgray", width=40, height=4)
label.pack(pady=10)

label.drop_target_register(DND_FILES)
label.dnd_bind("<<Drop>>", drop)

encrypt_btn = tk.Button(root, text="Select File to Encrypt", command=lambda: encrypt_file(filedialog.askopenfilename()), width=25, bg="green", fg="white")
encrypt_btn.pack(pady=5)

decrypt_btn = tk.Button(root, text="Select File to Decrypt", command=lambda: decrypt_file(filedialog.askopenfilename()), width=25, bg="blue", fg="white")
decrypt_btn.pack(pady=5)

exit_btn = tk.Button(root, text="Exit", command=root.quit, width=25, bg="red", fg="white")
exit_btn.pack(pady=5)

# Run GUI
root.mainloop()
