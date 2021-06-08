#! /usr/bin/env python3
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
    except json.JSONDecodeError:
        print("Login failed.")

def cmd_loop():
    cmd = ''
    while cmd is not "exit":
        cmd = input('> ').lower()
        if message is "help":
            print(" add:  add a new contact")
            print(" list: list all online contacts")
            print(" send: send file to contact")
            print(" exit: self-explanatory")

if __name__ == "__main__":
    main()
