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
    vault_folder = get_vault_directory()

    if os.name != 'nt' and os.geteuid() != 0:
        print("For copy passwords securely the Vault needs admin privilege!\nRestarting with admin privileges...")
        try:
            subprocess.run(["sudo", sys.executable, "-m", "gcmark.cli", *sys.argv[1:]], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error while trying to start with admin privileges: {e}")
            sys.exit(1)
        return

    try:
        file = open(os.path.join(vault_folder, "pm_db.mmf"), "r+")
        file.close()
    except FileNotFoundError:
        os.system("cls" if os.name == "nt" else "clear")
        print(ascii_images("vault"))
        print("\nVAULT SETUP\n\nCould not find pm_db.mmf in your directory, continuing to vault setup.")
        print(vault_setup(ascii_images("vault")))

    os.system("cls" if os.name == "nt" else "clear")
    print(ascii_images("lock"))
    hashed_pass = False
    c_salt, c_verifier, database = file_setup()
    error_count = 0

    while not hashed_pass:
        error_count = error_count + 1
        entered_pass = getpass.getpass("Enter Master Key: ")
        hashed_pass = verify_password(entered_pass, c_salt, c_verifier)
        if not hashed_pass:
            print("Incorrect master password. Try again.\n") if error_count < 4 else (
                print("Incorrect master password. Try again.\n\nYou can setup a new vault by deleting the 'pm_db.mmf' "
                      "at the 'gcmark-vault' folder.\nThis will delete all saved profiles and cannot be undone.\n")
            )
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
            timed_out = pwd_generate()

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

    if is_valid_input(user_response) and user_response == "y":
        vault_dir = get_vault_directory()
        display_alert("PURGE ACCOUNT CONFIRMATION")
        user_confirmation = timeout_input(
            "This action cannot be undone!\n\n"
            "Confirm by typing 'PURGE' (type (.c) to cancel): "
        )

        if user_confirmation == "PURGE":
            try:
                os.remove(os.path.join(vault_dir, "pm_db.mmf"))
                os.remove(os.path.join(vault_dir, "SALT.txt"))
                os.remove(os.path.join(vault_dir, "VERIFIER.txt"))
                os.system("cls" if os.name == "nt" else "clear")
                print(ascii_images("lock"))
                print(
                    "\n\nYour account was deleted. The program has automatically exited."
                )
                sys.exit()
            except ValueError:
                print("Could not purge profile (Error code: 01)")
                user_continue = timeout_input("\nPress enter to return to menu...")
                return cancel_or_timeout(user_continue)
        else:
            return False

    else:
        return cancel_or_timeout(user_response)


def change_master_password(hashed_pass, db):
    display_alert("CHANGE MASTER PASSWORD")
    password_provided = timeout_input(
        "Type your NEW password for your master account or leave blank to cancel: ")

    if is_valid_input(password_provided):
        if len(password_provided) < 6:
            print("Your password must have at least 6 characters.")
            user_continue = timeout_input("\nPress enter to return to menu...")
            return cancel_or_timeout(user_continue)
        vault_dir = get_vault_directory()
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
            file = open(os.path.join(vault_dir, "SALT.txt"), "wb")
            file.write(salt)
            file.close()
            del salt

            file = open(os.path.join(vault_dir, "VERIFIER.txt"), "wb")
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
            return cancel_or_timeout(user_continue)
    else:
        return cancel_or_timeout(password_provided)


def add_profile(hashed_pass, db):
    display_header("ADD A PROFILE")
    print("Type and submit (.c) to cancel.")
    add_domain = timeout_input("Website domain name: ")

    if not is_valid_input(add_domain):
        return cancel_or_timeout(add_domain)

    if add_domain in db:
        print("Profile already exists. You can update it or cancel by typing (.c).")

    add_user = timeout_input("Username: ")
    if not is_valid_input(add_user):
        return cancel_or_timeout(add_user)

    add_password = timeout_input("Password: ")
    if not is_valid_input(add_password):
        return cancel_or_timeout(add_password)

    db[add_domain] = {
        "username": encrypt_data(add_user, hashed_pass).decode("utf-8"),
        "password": encrypt_data(add_password, hashed_pass).decode("utf-8"),
    }
    overwrite_db(encrypt_data(json.dumps(db), hashed_pass).decode("utf-8"))
    print(f"Profile '{add_domain}' created/updated successfully!")
    user_continue = timeout_input("\nPress enter to return to menu...")

    return cancel_or_timeout(user_continue)


def find_profile_data(hashed_pass, db):
    display_header("FIND A PROFILE")
    print("Type and submit (.c) to cancel.")
    read_domain = timeout_input("What's the domain you're looking for? ")

    if is_valid_input(read_domain):
        try:
            domains = list(db.keys())
            matches = difflib.get_close_matches(read_domain, domains)

            if matches:
                print("\nClosest match:\n")
                i = 0

                for d in matches:
                    i = i + 1
                    domain_info = db[d]
                    username = str(
                        decrypt_data(bytes(domain_info["username"], encoding="utf-8"), hashed_pass).decode("utf-8")
                    )
                    print("PROFILE " + str(i) + ": " + d)
                    del d
                    print("Username: " + username + "\n")
                    del domain_info
                    del username

                user_continue = timeout_input(
                    "\nSelect the password to be copied to your clipboard (ex: 1), or leave blank to cancel: ")

                if user_continue.isdigit():

                    if 0 < int(user_continue) <= i:
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
                    return cancel_or_timeout(user_continue)
            else:
                print("Could not find a match. Try viewing all saved profiles.")
        except RuntimeError:
            print("Error finding profile.")

        user_continue = timeout_input("\nPress enter to return to menu...")

        return cancel_or_timeout(user_continue)

    return cancel_or_timeout(read_domain)


def edit_profile_data(hashed_pass, db):
    display_header("EDIT A PROFILE")
    print("You need to type the exact match.")
    edit_domain = timeout_input("Website domain name or submit (.c) to cancel at any time: ")

    if is_valid_input(edit_domain):
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

                return cancel_or_timeout(user_continue)

            if edit_user == " " or edit_user == "":
                edit_user = curr_user

            if edit_user == timeout_global_code:
                return True

            edit_password = timeout_input("New Password (press enter to keep the current: " + curr_password + "): ")

            if edit_password == ".c":
                print("Operation canceled.")
                user_continue = timeout_input("\nPress enter to return to menu...")

                return cancel_or_timeout(user_continue)

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

            return cancel_or_timeout(user_continue)

        except KeyError:
            print("This domain does not exist, changing to adding to new profile")
            user_continue = timeout_input("\nPress enter to return to menu...")

            return cancel_or_timeout(user_continue)

    return cancel_or_timeout(edit_domain)


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
                "\nSelect the password to be copied to your clipboard (ex: 1), or leave blank to cancel: ")

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

            if not user_continue.isdigit():
                return cancel_or_timeout(user_continue)

    except RuntimeError:
        print("Could not load all profiles")

    user_continue = timeout_input("\nPress enter to return to menu...")

    return cancel_or_timeout(user_continue)


def delete_profile_data(hashed_pass, db):
    display_alert("DELETE A PROFILE")
    del_domain = timeout_input("Write the exact saved domain name or leave blank to cancel): ")

    if is_valid_input(del_domain):
        if del_domain in db:
            confirm_deletion = timeout_input(f"Confirm deletion of profile {del_domain}? (y)es or (n)o:\n")
            if confirm_deletion == "y":
                print("Deleting profile...")
            else:
                return cancel_or_timeout(confirm_deletion)
        try:
            del db[del_domain]
            overwrite_db(encrypt_data(json.dumps(db), hashed_pass).decode("utf-8"))
            print("Deleted " + del_domain + " profile successfully!")
            user_continue = timeout_input("\nPress enter to return to menu...")

            return cancel_or_timeout(user_continue)

        except KeyError:
            print("Unable to find " + del_domain)
            user_continue = timeout_input("\nPress enter to return to menu...")

            return cancel_or_timeout(user_continue)

    else:
        return cancel_or_timeout(del_domain)


def pwd_generate():
    display_header("GENERATE RANDOM PASSWORD")
    pass_length = str(timeout_input("Password length (leave blank to cancel): "))

    if is_valid_input(pass_length):
        if not pass_length.isdigit():
            return cancel_or_timeout(pass_length)
        try:
            if int(pass_length) < 6:
                pass_length = str(6)
                print("\nPasswords must be at least 6 characters long, generating with 6 characters.")
            if int(pass_length) > 50:
                pass_length = str(50)
                print("\nPasswords must be at maximum 50 characters long, generating with 50 characters.")

            print(to_clipboard(str(generate_password(int(pass_length)))))
            user_continue = timeout_input("\nPress enter to return to menu...")

            return cancel_or_timeout(user_continue)

        except ValueError:
            print("Unable to generate password.")
            user_continue = timeout_input("\nPress enter to return to menu...")

            return cancel_or_timeout(user_continue)
    else:
        return cancel_or_timeout(pass_length)


def file_setup():
    vault_dir = get_vault_directory()

    with open(os.path.join(vault_dir, "SALT.txt"), "rb") as readfile:
        content1 = readfile.read()
        readfile.close()
    c_salt = content1

    with open(os.path.join(vault_dir, "VERIFIER.txt"), "rb") as readfile:
        content2 = readfile.read()
        readfile.close()
    c_verifier = content2

    file_path = os.path.join(vault_dir, "pm_db.mmf")
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


def generate_password(length):
    # if length < 6:
    #     length = 12

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
    vault_dir = get_vault_directory()
    file = open(os.path.join(vault_dir, "pm_db.mmf"), "w+")
    file.write(new_contents)
    file.close()


def is_valid_input(user_input):
    return user_input not in ["c", ".c", timeout_global_code, "", " "]


def cancel_or_timeout(user_input):
    if user_input == ".c":
        print("Operation canceled.")
        return False
    elif user_input == timeout_global_code:
        return True
    else:
        return False


if __name__ == "__main__":
    main()
