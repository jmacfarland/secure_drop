from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import os

class Identity(object):
    def __init__(self, salt=os.urandom(16)):
        #provide salt if not generating new kdf
        self.salt = salt
        self.kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )

    def decrypt(self, password, data):
        #password IN BYTES!
        return self.kdf.derive(password)
