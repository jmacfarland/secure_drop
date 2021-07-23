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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import os
import base64

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

        #not the best way to do it as the key is held in memory for the duration...
        #but I don't want to have to enter password just to save changes
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

    def _make_encryptor_session(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        return (cipher.encryptor(),
            base64.b64encode(key).decode(),
            base64.b64encode(iv).decode())

    def send_symmetric(self, encryptor, message):
        return encryptor.update(message) + encryptor.finalize()

    def _make_decryptor_session(self, key, iv):
        cipher = Cipher(
            algorithms.AES(
                base64.b64decode(key.encode())
            ),
            modes.CFB(
                base64.b64decode(iv.encode())
            )
        )
        return cipher.decryptor()

    def recv_symmetric(self, decryptor, message_cipher):
        msg = decryptor.update(message_cipher) + decryptor.finalize()
        return msg

    def sign(self, message):
        #returns signature of the message, not the message+signature
        return self.privkey.sign(
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
            'signature':base64.b64encode(self.sign(cipher_text)).decode()
        }).encode()

    def recv_asymmetric(self, data):
        data = json.loads(data.decode())
        #self._debug("RECV: " + str(data))
        message_cipher = base64.b64decode(data['message'].encode())
        signature = base64.b64decode(data['signature'].encode())
        message_plain = self.privkey.decrypt(
            message_cipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self._debug(message_plain)
        #TODO: vfy signature...
        #   should include author id in message_plain json,
        #   so can lookup author's claimed pubkey to verify
        return message_plain


    ##############################################
    #   SELF-FUNCTIONS
    ########################
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
    def get_name(self):
        return self.fullname

    def get_email(self):
        return self.email

    def get_contacts(self):
        return self.contacts

    def get_pubkey(self):
        return self.privkey.public_key()

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
