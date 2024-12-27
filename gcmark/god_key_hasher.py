import base64
import getpass
import os
import random

import argon2
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


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


def vault_setup():
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

    file = open("SALT.txt", "wb")
    file.write(salt)
    file.close()
    del salt

    file = open("VERIFIER.txt", "wb")
    file.write(encrypt_data("entered_master_correct", hashed_entered_pass))
    file.close()

    file = open("pm_db.mmf", "w+")
    file.write(str(encrypt_data("{}", hashed_entered_pass).decode('utf-8')))
    file.close()
    del hashed_entered_pass

    input("Your password vault was created. Access it using the pm_db.py file. Press ENTER to continue to login...")
