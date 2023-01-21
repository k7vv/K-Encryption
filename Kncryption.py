import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog

def encrypt_or_decrypt():
    choice = input("What would you like to do?\n1. Encrypt a file\n2. Decrypt a file\nEnter the number of your choice: ")
    if choice == "1":
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename()
        password = input("Enter the password for encryption: ")
        encrypt_file(file_path,password)
    elif choice == "2":
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename()
        password = input("Enter the password for decryption: ")
        decrypt_file(file_path,password)
    else:
        print("Invalid choice. Please enter 1 or 2.")

encrypt_or_decrypt()


def encrypt_file(file_name, password):
    # generate a salt
    salt = os.urandom(16)
    password = bytes(password, "utf-8")
    # derive a key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # create a Fernet object using the key
    f = Fernet(key)

    # read the contents of the file
    with open(file_name, "rb") as file:
        data = file.read()

    # encrypt the data
    encrypted_data = f.encrypt(data)

    # write the salt and encrypted data to a new file
    with open(file_name + ".encrypted", "wb") as file:
        file.write(salt + encrypted_data)

def decrypt_file(file_name, password):
    password = bytes(password, "utf-8")
    # read the salt and encrypted data from the file
    with open(file_name, "rb") as file:
        salt = file.read(16)
        encrypted_data = file.read()

    # derive the key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # create a Fernet object using the key
    f = Fernet(key)

    # decrypt the data
    decrypted_data = f.decrypt(encrypted_data)

    # write the decrypted data to a new file
    with open(file_name + ".decrypted", "wb") as file:
        file.write(decrypted_data)

root = tk.Tk()
root.withdraw()
file_path = filedialog.askopenfilename()
password = input("Enter the password for encryption: ")
encrypt_or_decrypt()