#! /usr/bin/env python3
from user import User

def main():
    u = User()
    if not u.load_from_file():
        #no user exists, register new
        u.register()
        u.save_to_file()
    else:
        u.login()

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
