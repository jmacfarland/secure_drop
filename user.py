#! /usr/bin/env python3

#from Crypto.Hash import SHA256 as hash
import json
import crypt
import getpass
from hmac import compare_digest as compare_hash

class User(object):
    def register(self):
        self.fullname = input("Full Name: ")
        self.email = input("Email: ")
        self.salt = crypt.mksalt()
        hash1 = 'abcd'
        hash2 = 'efgh'
        while hash1 != hash2:
            print("Enter your password:")
            hash1 = crypt.crypt(getpass.getpass(),self.salt)
            print("Enter your password again:")
            hash2 = crypt.crypt(getpass.getpass(),self.salt)
            if hash1 == hash2:
                self.hash = hash1
                print("Thank you. User registered.")
            else:
                print("Whoops, try again.")

    def login(self):
        temp_pass = getpass.getpass()
        if compare_hash(crypt.crypt(temp_pass,self.salt),self.hash):
            print("LOGGED IN :))))")
            #decrypt user key using pass
            #blank key
        else:
            print("Sorry, try again.")

    # FILE IO
    ################################
    def save_to_file(self, fname='user.txt'):
        with open(fname, 'w') as outfile:
            outfile.write(repr(self))

    def load_from_file(self, fname='user.txt'):
        try:
            with open(fname, 'r') as infile:
                data = json.loads(infile.read())
                self.fullname = data['fullname']
                self.email = data['email']
                self.salt = data['salt']
                self.hash = data['hash']
        except FileNotFoundError:
            return False
        return True

    # GETTERS
    ################################
    def get_name(self):
        return self.fullname

    def get_email(self):
        return self.email

    # UTILS
    ################################
    def __repr__(self):
        return json.dumps(self.__dict__)

if __name__ == "__main__":
    a = User("abc", "def")
