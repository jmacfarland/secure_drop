#! /usr/bin/env python3

#from Crypto.Hash import SHA256 as hash
import json
import crypt
import getpass
from cryptography.hazmat.primitives import padding as padding_sym
from hmac import compare_digest as compare_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
#from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import os
import base64

from utils import make_encryptor, make_decryptor

class User(object):
    def _debug(self, message):
        if self.debug:
            print("%s: %s"%(self.email,message))

    def register(self, fullname=None, email=None, debug=False):
        self.debug=debug
        if not fullname:
            self.fullname = input("Full Name: ")
        else:
            self.fullname = fullname

        if not email:
            self.email = input("Email: ")
        else:
            self.email = email
        self.salt = os.urandom(16)
        self.privkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.contacts = {}

        #precompute self-encryption key on register so user doesn't have to re-enter
        #   password just to save changes at the end of a session
        kdf = Scrypt(
            salt=self.salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        if not self.debug:
            key = kdf.derive(getpass.getpass().encode())
        else: #TODO: remove this after testing is done
            key = kdf.derive("test".encode())
        self.f = Fernet(base64.urlsafe_b64encode(key))

    def add_contact(self, email, pubkey):
        #self._debug("Adding contact %s: %s"%(email,pubkey))
        self.contacts[email] = pubkey

    def sign(self, message):
        #returns signature of the message, b64e, str
        sig = self.privkey.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(sig).decode() #b64 in str format

    def verify_signature(self, email, message, signature):
        key = serialization.load_pem_public_key(
            self.contacts[email],
            backend=default_backend()
        )
        key.verify(
            base64.b64decode(signature),
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def send_asymmetric(self, email, message):
        #MESSAGE must be bytes
        key = serialization.load_pem_public_key(
            self.contacts[email],
            backend=default_backend()
        )
        cipher_text = key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return json.dumps({
            'message':base64.b64encode(cipher_text).decode(),
            'signature':self.sign(message) #signature is already b64
        }).encode()

    def recv_asymmetric(self, data):
        data = json.loads(data.decode())
        #self._debug("RECV: " + str(data))
        message_cipher = base64.b64decode(data['message'].encode())
        message_plain = self.privkey.decrypt(
            message_cipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #self._debug(message_plain)
        return message_plain, data["signature"]


    ##############################################
    #   SELF-FUNCTIONS
    ########################
    def encrypt(self):
        data = {}
        data["secret"] = base64.b64encode(
            self.f.encrypt(
                repr(self).encode())
            ).decode()
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
        #derive and attach self-encryption key to the User object, so user doesn't have
        #   to re-enter password just to save changes.
        #   I realize this is less secure, since an attacker with the ability to spy
        #   on this program's memory-space would be able to grab the decryption key,
        #   BUT- if they can do that, they can already grab all of the data that the
        #   key could decrypt, so it's kinda moot I think...
        #       UNLESS I add per-message derivation of the private key, but that's
        #       waaaay too many layers for me to consider right now
        self.f = Fernet(base64.urlsafe_b64encode(key))
        return json.loads(
            self.f.decrypt(
                base64.b64decode(
                    data["secret"]
                )
            )
        )

    # FILE IO
    ################################
    def save_to_file(self, fname='user.txt'):
        with open(fname, 'w') as outfile:
            outfile.write(str(self.encrypt()))

    def load_from_file(self, fname='user.txt'):
        try:
            with open(fname, 'r') as infile:
                data = json.loads(infile.read())
                plain = self.decrypt(data)
                self.fullname = plain['fullname']
                self.email = plain['email']
                self.privkey = serialization.load_pem_private_key(
                    plain['privkey'],
                    password=None,
                    backend=default_backend()
                )
                self.contacts = plain['contacts']
        except FileNotFoundError:
            self.register()
            self.save_to_file()

    # GETTERS
    ################################
    def get_pubkey_pem(self):
        return self.privkey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # UTILS
    ################################
    def __repr__(self):
        return json.dumps({
            "fullname":self.fullname,
            "email":self.email,
            "privkey":self.privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            "contacts":self.contacts
        })

if __name__ == "__main__":
    b = User()
    print(b.load_from_file())

    print(repr(b))
