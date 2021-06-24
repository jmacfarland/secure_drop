import os
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers import Cipher


def _pad_to(msg, length):
    '''
    format: {length_of_message}.{message}{padding}
    '''
    msg = str(len(msg)).encode() + b'.' + msg.encode()
    pad = os.urandom(length-(len(msg) % length))
    return msg + pad


def _de_pad(msg):
    '''
    Retrieve length of the valid message, then
    strip away the remaining padding.
    '''
    length, msg = msg.split(b'.')
    if int(length) >= len(msg) or int(length) < 0:
        return msg
    return msg[0:int(length)]


class Session():
    '''
    ECDHE_AES256 message passing
    USAGE:
        # initialize
        alice = Session()
        bob = Session()
        # handshake bob->alice
        bob_pub = bob.send_pubkey()
        alice.recv_pubkey(bob_pub)
        # handshake alice->bob
        alice_pub = alice.send_pubkey()
        bob.recv_pubkey(alice_pub)
        # message alice->bob
        alice_message_ciphertext = alice.send_msg(b'super secret message')
        bob_message_received = bob.recv_msg(alice_message_ciphertext)
    '''

    def __init__(self):
        # self.params = params
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(),
            default_backend()
        )
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.derived_key = None

    def send_pubkey(self):
        return base64.b64encode(self.public_key)

    def recv_pubkey(self, peer_key_raw):
        try:
            self.peer_key = serialization.load_pem_public_key(
                base64.b64decode(peer_key_raw),
                backend=default_backend()
            )
            self.derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(self.private_key.exchange(
                ec.ECDH(),
                self.peer_key
            )
            )
            return True
        except:
            return False

    def send_msg(self, msg):
        iv = os.urandom(16)
        enc = Cipher(
            AES(self.derived_key),
            CBC(iv),
            backend=default_backend()
        ).encryptor()
        msg_json = json.dumps({
            'message': msg,
            'test': 'Jamie'
        })
        return self._serialize(enc.update(_pad_to(msg_json, 16)) + enc.finalize(), iv)

    def recv_msg(self, msg):
        #try:
        msg, iv = self._deserialize(msg)
        # if self.peer_key.verify(signature, msg, ec.ECDSA(hashes.SHA256())):
        dec = Cipher(
            AES(self.derived_key),
            CBC(iv),
            backend=default_backend()
        ).decryptor()
        msg_json = json.loads(
            _de_pad(
                dec.update(msg) + dec.finalize()
            ).decode()
        )
        print(msg_json)
        return msg_json['message']
        # else:
        #    return b'Invalid signature detected! Message discarded'
        #except:
        #    return None

    def _serialize(self, msg, iv):
        '''
        format: {message}.{initialization_vector}.{signature}
        '''
        signature = self.private_key.sign(
            msg,
            ec.ECDSA(hashes.SHA256())
        )
        return base64.b64encode(msg + b'.' + iv)  # + b'.' + signature)

    def _deserialize(self, msg):
        return base64.b64decode(msg).split(b'.')
