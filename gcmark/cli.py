import sys
import os
import subprocess
import difflib
import json
import string
import sys
import threading
import time
import platform

import keyboard as kb
import pyperclip
import secrets
from inputimeout import inputimeout, TimeoutOccurred

current_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.dirname(current_dir)
if base_dir not in sys.path:
    sys.path.append(base_dir)

from gcmark.god_key_hasher import *

from gcmark.utils import ascii_images

timeout_global_code = "*TIMEOUT*"


def main():
    if os.name != 'nt' and os.geteuid() != 0:
        print("Restarting with admin privileges...")
        try:
            subprocess.run(["sudo", sys.executable, "-m", "gcmark.cli", *sys.argv[1:]], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error while trying to start with admin privileges: {e}")
            sys.exit(1)
        return

    try:
        file = open("pm_db.mmf", "r+")
        file.close()
    except FileNotFoundError:
        os.system("cls" if os.name == "nt" else "clear")
        print(ascii_images("vault"))
        print("\nVAULT SETUP\n\nCould not find pm_db.mmf in local directory, continuing to vault setup.")
        print(vault_setup())

    os.system("cls" if os.name == "nt" else "clear")
    print(ascii_images("lock"))
    hashed_pass = False
    c_salt, c_verifier, database = file_setup()
    while not hashed_pass:
        entered_pass = getpass.getpass("Enter Master Key: ")
        hashed_pass = verify_password(entered_pass, c_salt, c_verifier)
        if not hashed_pass:
            print("Incorrect master password. Try again.\n")
    if hashed_pass:
        del entered_pass
        main_pwd_manager(hashed_pass, database)
        del hashed_pass
        del c_salt
        del c_verifier
        del database


def main_pwd_manager(hashed_pass, contents):
    os.system("cls" if os.name == "nt" else "clear")
    db = json.loads(decrypt_data(contents, hashed_pass).decode("utf-8"))
    timed_out = False
    while not timed_out:
        os.system("cls" if os.name == "nt" else "clear")
        print(ascii_images("check"))
        print(ascii_images("divider"))
        print(
            "\n(a)dd profile | (f)ind profile data  | (e)dit profile data | (r)ead all profiles | (d)elete profile "
            "data\n(g)enerate password | (c)hange master password | e(x)it | (p)urge account\n"
        )
        user_cmd = timeout_input("What would you like to do? ")
        print("\n")

        if user_cmd != timeout_global_code:
            user_cmd = user_cmd.lower()

        if user_cmd == "a":
            timed_out = add_profile(hashed_pass, db)

        if user_cmd == "f":
            timed_out = find_profile_data(hashed_pass, db)

        if user_cmd == "r":
            timed_out = read_all_profiles(hashed_pass, db)

        if user_cmd == "e":
            timed_out = edit_profile_data(hashed_pass, db)

        if user_cmd == "d":
            timed_out = delete_profile_data(hashed_pass, db)

        if user_cmd == "g":
            timed_out = pwd_generate(hashed_pass, db)

        if user_cmd == "c":
            timed_out = change_master_password(hashed_pass, db)

        if user_cmd == "p":
            timed_out = purge_account()

        if user_cmd == "x":
            os.system("cls" if os.name == "nt" else "clear")
            timed_out = True

        if user_cmd == timeout_global_code:
            timeout_cleanup()
            timed_out = True

    del hashed_pass
    del contents
    del db


def purge_account():
    display_alert("PURGE ACCOUNT")
    user_response = timeout_input(
        "Proceed with caution, this will delete all saved profiles and cannot be undone.\n\n"
        "Would you like to purge your account? (type (y) for purge or (.c) to cancel)? "
    )
    if (user_response != ".c" and user_response != "" and user_response != " "
            and user_response != timeout_global_code and user_response == "y"):
        display_alert("PURGE ACCOUNT CONFIRMATION")
        user_confirmation = timeout_input(
            "This action cannot be undone!\n\n"
            "Confirm by typing 'PURGE' (type (.c) to cancel): "
        )
        if user_confirmation == "PURGE":
            try:
                os.remove("pm_db.mmf")
                os.remove("SALT.txt")
                os.remove("VERIFIER.txt")
                os.system("cls" if os.name == "nt" else "clear")
                print(ascii_images("lock"))
                print(
                    "\n\nYour account was deleted. The program has automatically exited."
                )
                sys.exit()
            except ValueError:
                print("Could not purge profile (Error code: 01)")
                user_continue = timeout_input("\nPress enter to return to menu...")
                if user_continue != timeout_global_code:
                    return False
                else:
                    return True
        else:
            return False
    else:
        if user_response != timeout_global_code:
            return False
        else:
            return True


def change_master_password(hashed_pass, db):
    display_alert("CHANGE MASTER PASSWORD")
    password_provided = timeout_input(
        "What would you like your master password to be (type and submit (.c) to cancel)? ")
    if (password_provided != ".c" and password_provided != "" and password_provided != " "
            and password_provided != "c" and password_provided != timeout_global_code):
        password = password_provided.encode()
        salt = os.urandom(random.randint(16, 256))
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )
        hashed_entered_pass = base64.urlsafe_b64encode(kdf.derive(password))
        try:
            i = -1
            domains = list(db.keys())
            for e in db:
                i = i + 1

                username = str(
                    decrypt_data(bytes(db[domains[i]]["username"], encoding="utf-8"), hashed_pass).decode("utf-8")
                )

                password = str(
                    decrypt_data(bytes(db[domains[i]]["password"], encoding="utf-8"), hashed_pass).decode("utf-8")
                )

                db[domains[i]] = {
                    "username": str(encrypt_data(username, hashed_entered_pass).decode("utf-8")),
                    "password": str(encrypt_data(password, hashed_entered_pass).decode("utf-8")),
                }

                del e
                del username
                del password

            del domains
            file = open("SALT.txt", "wb")
            file.write(salt)
            file.close()
            del salt

            file = open("VERIFIER.txt", "wb")
            file.write(encrypt_data("entered_master_correct", hashed_entered_pass))
            file.close()

            overwrite_db(encrypt_data(json.dumps(db), hashed_entered_pass).decode("utf-8"))
            del hashed_entered_pass
            del hashed_pass
            os.system("cls" if os.name == "nt" else "clear")
            print("Master password changed successfully! Log in again to access the password manager.")
            timeout_input("\nPress enter to logout..")
            return True
        except ValueError:
            print("Could not change master password (Error code: 01)")
            user_continue = timeout_input("\nPress enter to return to menu...")
            if user_continue != timeout_global_code:
                return False
            else:
                return True
    else:
        if password_provided != timeout_global_code:
            return False
        else:
            return True


def add_profile(hashed_pass, db):
    display_header("ADD A PROFILE")
    print("Type and submit (.c) to cancel.")
    add_domain = timeout_input("Website domain name: ")
    if add_domain == ".c":
        print("Operation canceled.")
        return False
    if add_domain != ".c" and add_domain != timeout_global_code:
        add_user = timeout_input("Username: ")
    if add_user != ".c" and add_user != timeout_global_code:
        add_password = timeout_input("Password: ")
    if add_domain != ".c" and add_domain != timeout_global_code and add_user != timeout_global_code and add_password != timeout_global_code:
        db[add_domain] = {
            "username": str(encrypt_data(add_user, hashed_pass).decode("utf-8")),
            "password": str(encrypt_data(add_password, hashed_pass).decode("utf-8")),
        }
        overwrite_db(encrypt_data(json.dumps(db), hashed_pass).decode("utf-8"))
        print("Created " + add_domain + " profile successfully!")
    if add_domain == timeout_global_code or add_user == timeout_global_code or add_password == timeout_global_code:
        return True


def find_profile_data(hashed_pass, db):
    display_header("FIND A PROFILE")
    print("Type and submit (.c) to cancel.")
    read_domain = timeout_input("What's the domain you're looking for? ")

    if read_domain != ".c" and read_domain != timeout_global_code:
        try:
            domains = list(db.keys())
            matches = difflib.get_close_matches(read_domain, domains)

            if matches:
                print("\nClosest match:\n")
                i = 1

                for d in matches:
                    domain_info = db[d]
                    username = str(
                        decrypt_data(bytes(domain_info["username"], encoding="utf-8"), hashed_pass).decode("utf-8")
                    )
                    print("PROFILE " + str(i) + ": " + d)
                    del d
                    print("Username: " + username + "\n")
                    del domain_info
                    del username
                    i = i + 1

                user_continue = timeout_input(
                    "\nSelect the password to be copied to your clipboard (ex: 1), or type (.c) to cancel: ")

                if user_continue.isdigit():

                    if int(user_continue) > 0:
                        try:
                            password = str(
                                decrypt_data(
                                    bytes(db[str(matches[int(user_continue) - 1])]["password"], encoding="utf-8"),
                                    hashed_pass).decode("utf-8")
                            )
                            print("\n" + to_clipboard(password))
                            del password
                        except ValueError:
                            print("\nUnable to find profile corresponding to " + str(user_continue) + ".")
                    else:
                        print("\nThere are no profiles corresponding to that number.")

                if not user_continue.isdigit():

                    if user_continue != timeout_global_code:
                        return False
                    else:
                        return True
            else:
                print("Could not find a match. Try viewing all saved profiles.")

        except RuntimeError:
            print("Error finding profile.")
        user_continue = timeout_input("\nPress enter to return to menu...")

        if user_continue != timeout_global_code:
            return False
        else:
            return True

    if read_domain == ".c":
        print("Operation canceled.")
        print("\nReturning to Menu")
        return False

    if read_domain == timeout_global_code:
        return True


def edit_profile_data(hashed_pass, db):
    display_header("EDIT A PROFILE")
    edit_domain = timeout_input("Website domain name (submit (.c) to cancel): ")

    if edit_domain != ".c" and edit_domain != timeout_global_code:
        try:
            domain_info = db[edit_domain]
            curr_user = str(
                decrypt_data(bytes(domain_info["username"], encoding="utf-8"), hashed_pass).decode("utf-8")
            )
            curr_password = str(
                decrypt_data(bytes(domain_info["password"], encoding="utf-8"), hashed_pass).decode("utf-8")
            )

            edit_user = timeout_input("New Username (press enter to keep the current: " + curr_user + "): ")
            if edit_user == ".c":
                print("Operation canceled.")
                user_continue = timeout_input("\nPress enter to return to menu...")

                if user_continue != timeout_global_code:
                    print("Returning to menu")
                    return False
                else:
                    return True

            if edit_user == " " or edit_user == "":
                edit_user = curr_user

            if edit_user == timeout_global_code:
                return True

            edit_password = timeout_input("New Password (press enter to keep the current: " + curr_password + "): ")
            if edit_password == " " or edit_password == "":
                edit_password = curr_password

            if edit_password == timeout_global_code:
                return True

            db[edit_domain] = {
                "username": str(encrypt_data(edit_user, hashed_pass).decode("utf-8")),
                "password": str(
                    encrypt_data(edit_password, hashed_pass).decode("utf-8")
                ),
            }
            overwrite_db(encrypt_data(json.dumps(db), hashed_pass).decode("utf-8"))
            print("Updated " + edit_domain + " profile successfully!")
            del edit_domain
            del curr_user
            del edit_user
            del curr_password
            del edit_password
            del db
            user_continue = timeout_input("\nPress enter to return to menu...")

            if user_continue != timeout_global_code:
                print("Returning to menu")
                return False
            else:
                return True

        except KeyError:
            print("This domain does not exist, changing to adding to new profile")
            user_continue = timeout_input("\nPress enter to return to menu...")

            if user_continue != timeout_global_code:
                print("Returning to menu")
                return False
            else:
                return True

    if edit_domain != timeout_global_code:
        print("Returning to menu")
        return False
    else:
        return True


def read_all_profiles(hashed_pass, db):
    display_header("READING ALL PROFILES")
    try:
        i = 0
        domains = list(db.keys())
        for e in db:
            i = i + 1
            username = str(
                decrypt_data(bytes(db[e]["username"], encoding="utf-8"), hashed_pass).decode("utf-8")
            )
            print("PROFILE " + str(i) + ": " + e)
            print("Username: " + username)
            del e
            del username
            print(ascii_images("divider"))

        if i == 0:
            print("No saved profiles")

        if i > 0:
            user_continue = timeout_input(
                "\nSelect the password to be copied to your clipboard (ex: 1), or type (.c) to cancel: ")

            if user_continue.isdigit():
                if 0 < int(user_continue) <= i:
                    try:
                        password = str(
                            decrypt_data(bytes(db[str(domains[int(user_continue) - 1])]["password"], encoding="utf-8"),
                                         hashed_pass).decode("utf-8")
                        )
                        print("\n" + to_clipboard(password))
                        del password
                    except:
                        print("\nUnable to find profile corresponding to " + str(user_continue) + ".")
                else:
                    print("\nThere are no profiles corresponding to that number.")

            if not user_continue.isdigit() and user_continue != timeout_global_code:
                return False

            if user_continue == timeout_global_code:
                return True

    except RuntimeError:
        print("Could not load all profiles")

    user_continue = timeout_input("\nPress enter to return to menu...")

    if user_continue != timeout_global_code:
        print("Returning to menu")
        return False
    else:
        return True


def delete_profile_data(hashed_pass, db):
    display_alert("DELETE A PROFILE")
    del_domain = timeout_input("Write the exact saved domain name (type (.c) to cancel): ")

    if del_domain != ".c" and del_domain != timeout_global_code:
        try:
            del db[del_domain]
            overwrite_db(encrypt_data(json.dumps(db), hashed_pass).decode("utf-8"))
            print("Deleted " + del_domain + " profile successfully!")
            user_continue = timeout_input("\nPress enter to return to menu...")

            if user_continue != timeout_global_code:
                print("Returning to menu")
                return False
            else:
                return True

        except KeyError:
            print("Unable to find " + del_domain)
            user_continue = timeout_input("\nPress enter to return to menu...")

            if user_continue != timeout_global_code:
                print("Returning to menu")
                return False
            else:
                return True

    else:
        if del_domain != timeout_global_code:
            print("Returning to menu")
            return False
        else:
            return True


def pwd_generate(hashed_pass, db):
    display_header("GENERATE RANDOM PASSWORD")
    pass_length = str(timeout_input("Password length (type (.c) to cancel): "))

    if pass_length != ".c" and pass_length != timeout_global_code:
        try:
            if int(pass_length) < 6:
                pass_length = str(12)
                print("\nPasswords must be at least 6 characters long.")
            print(to_clipboard(str(generate_password(int(pass_length)))))
            user_continue = timeout_input("\nPress enter to return to menu...")

            if user_continue != timeout_global_code:
                print("Returning to menu")
                return False
            else:
                return True

        except ValueError:
            print("Unable to generate password.")
            user_continue = timeout_input("\nPress enter to return to menu...")

            if user_continue != timeout_global_code:
                print("Returning to menu")
                return False
            else:
                return True
    else:
        if pass_length != timeout_global_code:
            print("Returning to menu")
            return False
        else:
            return True


def file_setup():
    with open("SALT.txt", "rb") as readfile:
        content1 = readfile.read()
        readfile.close()
    c_salt = content1

    with open("VERIFIER.txt", "rb") as readfile:
        content2 = readfile.read()
        readfile.close()
    c_verifier = content2

    file_path = "pm_db.mmf"
    file = open(file_path, "rb")
    content3 = file.read()
    data_base = content3

    return c_salt, c_verifier, data_base


def display_header(title):
    os.system("cls" if os.name == "nt" else "clear")
    print(ascii_images("check"))
    print(ascii_images("divider"))
    print(str(title) + "\n")


def display_alert(title):
    os.system("cls" if os.name == "nt" else "clear")
    print(ascii_images("alert"))
    print(ascii_images("divider"))
    print(str(title) + "\n")


def clear_clipboard_timer():
    if os.name == "nt":
        kb.wait('ctrl+v')
        time.sleep(0.5)
        pyperclip.copy("")

    elif os.name == "posix":
        if platform.system() == "Darwin":
            while True:
                if kb.is_pressed([55, 9]):
                    time.sleep(0.5)
                    pyperclip.copy("")
                    break
        else:
            kb.wait('ctrl+v')
            time.sleep(0.5)
            pyperclip.copy("")


def to_clipboard(input_to_copy):
    pyperclip.copy(str(input_to_copy))
    del input_to_copy
    threading.Thread(target=clear_clipboard_timer).start()
    return "Password was saved to clipboard. It will be removed from your clipboard as soon as you paste it."


def timeout_cleanup():
    os.system("cls" if os.name == "nt" else "clear")
    print(ascii_images("lock"))
    print(
        "\n\nYour session expired. For your security, the program has automatically exited. All submitted data is "
        "still saved."
    )
    sys.exit()


def timeout_input(caption):
    try:
        user_input = inputimeout(prompt=caption, timeout=90)
    except TimeoutOccurred:
        user_input = timeout_global_code
        timeout_cleanup()
    return user_input


def generate_password(length=12):
    if length < 6:
        length = 12

    uppercase_loc = secrets.choice(string.digits)
    symbol_loc = secrets.choice(string.digits)
    lowercase_loc = secrets.choice(string.digits)
    password = ""
    pool = string.ascii_letters + string.punctuation

    for i in range(length):
        if i == uppercase_loc:
            password += secrets.choice(string.ascii_uppercase)
        elif i == lowercase_loc:
            password += secrets.choice(string.ascii_lowercase)
        elif i == symbol_loc:
            password += secrets.choice(string.punctuation)
        else:
            password += secrets.choice(pool)
    return password


def encrypt_data(data_input, hashed_pass):
    message = data_input.encode()
    f = Fernet(hashed_pass)
    encrypted = f.encrypt(message)
    return encrypted


def decrypt_data(data_input, hashed_pass):
    f = Fernet(hashed_pass)
    decrypted = f.decrypt(data_input)
    return decrypted


def verify_password(password_provided, c_salt, c_verifier):
    verifier = c_verifier
    password = password_provided.encode()
    salt = c_salt
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    hashed_entered_pass = base64.urlsafe_b64encode(
        kdf.derive(password)
    )

    try:
        pass_verifier = decrypt_data(verifier, hashed_entered_pass)
        if pass_verifier == b"entered_master_correct":
            return hashed_entered_pass
    except:
        return False


def overwrite_db(new_contents):
    file = open("pm_db.mmf", "w+")
    file.write(new_contents)
    file.close()


if __name__ == "__main__":
    main()
