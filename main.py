#! /usr/bin/env python3
from cryptography.fernet import InvalidToken as InvalidTokenError
from user import User
import json

def main():
    u = User()
    try:
        u.load_from_file()
    except FileNotFoundError:
        #no user exists, register new
        u.register()
        u.save_to_file()
    except InvalidTokenError:
        print("Login failed.")
        exit(0)

    cmd_loop(u)

def cmd_loop(acct):
    cmd = ''
    print("Welcome to Secure Drop, {0}".format(acct.get_name()))
    while cmd != "exit":
        cmd = input('> ').lower()
        if cmd == "help":
            print("---> add:  add a new contact")
            print("---> list: list all online contacts")
            print("---> send: send file to contact")
            print("---> exit: exit")
        elif cmd == "add":
            acct.add_contact(input("Contact name: "), input("Contact email: "))
        elif cmd == "list":
            for c in acct.get_contacts():
                print(c)
        elif cmd == "show":
            print(repr(acct))
    acct.save_to_file()
    exit(0)

if __name__ == "__main__":
    main()
