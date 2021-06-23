#! /usr/bin/env python3

#from Crypto.Hash import SHA256 as hash
import json
import crypt
import getpass
from hmac import compare_digest as compare_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import os
import base64

class User(object):
    def register(self):
        self.fullname = input("Full Name: ")
        self.email = input("Email: ")
        self.salt = os.urandom(16)
        self.privkey = Ed25519PrivateKey.generate()
        self.contacts = []

        #not the best way to do it as the key is held in memory for the duration...
        #but I don't want to have to enter password just to save changes
        kdf = Scrypt(
            salt=self.salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        key = kdf.derive(getpass.getpass().encode())
        self.f = Fernet(base64.urlsafe_b64encode(key))

    def add_contact(self, name, email):
        self.contacts.append({
            "name":name,
            "email":email
        })

    def encrypt(self):
        data = {}

        data["secret"] = base64.b64encode(
            self.f.encrypt(
                repr(self).encode())).decode()
        data["salt"] = base64.b64encode(self.salt).decode()
        return json.dumps(data)

    def decrypt(self,data):
        self.salt = base64.b64decode(data["salt"].encode())
        kdf = Scrypt(
            salt=self.salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        key = kdf.derive(getpass.getpass().encode())
        self.f = Fernet(base64.urlsafe_b64encode(key))
        return json.loads(
            self.f.decrypt(
                base64.b64decode(
                    data["secret"])))

    # FILE IO
    ################################
    def save_to_file(self, fname='user.txt'):
        with open(fname, 'w') as outfile:
            outfile.write(str(self.encrypt()))

    def load_from_file(self, fname='user.txt'):
        with open(fname, 'r') as infile:
            data = json.loads(infile.read())
            plain = self.decrypt(data)
            self.fullname = plain['fullname']
            self.email = plain['email']
            self.privkey = Ed25519PrivateKey.from_private_bytes(
                base64.b64decode(plain['privkey'].encode()))
            self.contacts = plain['contacts']

    # GETTERS
    ################################
    def get_name(self):
        return self.fullname

    def get_email(self):
        return self.email

    def get_contacts(self):
        return self.contacts

    # UTILS
    ################################
    def __repr__(self):
        return json.dumps({
            "fullname":self.fullname,
            "email":self.email,
            "privkey":base64.b64encode(
                self.privkey.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
            )).decode(),
            "contacts":self.contacts
        })

if __name__ == "__main__":
    b = User()
    print(b.load_from_file())

    print(repr(b))
