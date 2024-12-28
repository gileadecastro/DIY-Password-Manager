import base64
import getpass
import os
import random

import argon2
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def get_vault_directory():
    user_home = os.path.expanduser("~")
    vault_dir = os.path.join(user_home, "gcmark-vault")
    if not os.path.exists(vault_dir):
        os.makedirs(vault_dir)
    return vault_dir


def encrypt_data(input_data, hashed_pass):
    message = input_data.encode()
    f = Fernet(hashed_pass)
    encrypted = f.encrypt(message)
    return encrypted


def decrypt_data(input_data, hashed_pass):
    f = Fernet(hashed_pass)
    decrypted = f.decrypt(input_data)
    return decrypted


def argon_2_hash(input_data):

    ph = PasswordHasher(time_cost=32, memory_cost=8589935000, parallelism=8, hash_len=256, salt_len=32, encoding='utf-8',
                        type=argon2.Type.ID)
    ph_hash = ph.hash(input_data.encode())

    return ph_hash


def vault_setup(vault_img):
    vault_dir = get_vault_directory()
    password_provided = getpass.getpass("What would you like your master password to be? ")
    while len(password_provided) < 6:
        os.system("cls" if os.name == "nt" else "clear")
        print(vault_img)
        print("\nVAULT SETUP\n")
        print("Password must be at least 6 characters long.")
        password_provided = getpass.getpass("What would you like your master password to be? ")
    password = password_provided.encode()
    salt = os.urandom(32)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    hashed_entered_pass = base64.urlsafe_b64encode(kdf.derive(password))

    with open(os.path.join(vault_dir, "SALT.txt"), "wb") as file:
        file.write(salt)
        file.close()
    del salt

    with open(os.path.join(vault_dir, "VERIFIER.txt"), "wb") as file:
        file.write(encrypt_data("entered_master_correct", hashed_entered_pass))
        file.close()

    with open(os.path.join(vault_dir, "pm_db.mmf"), "w+") as file:
        file.write(str(encrypt_data("{}", hashed_entered_pass).decode('utf-8')))
        file.close()
    del hashed_entered_pass

    os.system("cls" if os.name == "nt" else "clear")
    print(vault_img)

    input(f"\nYour password vault was created in '{vault_dir}'. "
          "\nIf you lose your master password, you will lose access to your vault."
          f"\nIf it occurs, delete the 'pm_db.mmf' file located at {vault_dir} and run the setup again."
          "\nPress ENTER to continue to login...")
