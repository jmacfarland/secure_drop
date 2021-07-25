#! /usr/bin/env python3
from user import User
from utils import make_encryptor, make_decryptor
from main import sendfile
import json
import hashlib
import unittest

def get_digest(file_path):
    h = hashlib.sha256()

    with open(file_path, 'rb') as file:
        while True:
            # Reading is buffered, so we can read smaller chunks.
            chunk = file.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)
        file.close()
    return h.hexdigest()

class EncryptionTest(unittest.TestCase):
    def setUp(self):
        self.one = User()
        self.one.register("one", "one@test.com", debug=True)

        self.two = User()
        self.two.register("two", "two@test.com", debug=True)
        pubkey_one = self.one.get_pubkey_pem()
        self.two.add_contact("one@test.com", pubkey_one)

        pubkey_two = self.two.get_pubkey_pem()
        self.one.add_contact("two@test.com", pubkey_two)

    def test_send_asymmetric_msg(self):
        msg_orig = b'test'*10
        msg_cipher = self.one.send_asymmetric("two@test.com",msg_orig)
        msg_plain, sig = self.two.recv_asymmetric(msg_cipher)
        self.assertEqual(len(msg_plain), len(msg_orig), "messages not the same length")

    def test_send_symmetric_msg(self):
        '''
        Test of using asymmetric encryption to send small message containing
        information to construct a symmetric encryption key, which can efficiently
        encrypt large amounts of data
        '''
        s1, key1, iv1 = make_encryptor()
        keyinfo = json.dumps({"key":key1, "iv":iv1}).encode()
        ct = self.one.send_asymmetric("two@test.com",keyinfo)

        pt, sig = self.two.recv_asymmetric(ct) #pt == plaintext
        self.assertEqual(pt, keyinfo, "keyinfo was not as expected")
        data = json.loads(pt.decode())
        s2, _, _ = make_decryptor(data['key'], data['iv'])

        msg_orig = b'a secret message'
        msg_cipher = s1.update(msg_orig) + s1.finalize()
        msg_plain = s2.update(msg_cipher) + s2.finalize()
        self.assertEqual(msg_plain, msg_orig)

    def test_sendfile(self):
        '''
        Test of encrypting large file (64KiB), to verify:
            - size of plaintext == size of ciphertext
            - hash of pre-encryption plaintext == hash of post-decryption plaintext
        '''
        s1, key1, iv1 = make_encryptor()
        ct = self.one.send_asymmetric("two@test.com",
            json.dumps({"key":key1, "iv":iv1}).encode()
        )

        pt, sig = self.two.recv_asymmetric(ct)
        data = json.loads(pt.decode())
        s2, _, _ = make_decryptor(data['key'], data['iv'])

        #########################
        testfile = "text/text_64k.txt"
        file = open(testfile, "rb")
        plain = file.read()
        file.close()
        expected_hash = get_digest(testfile)
        cipher = s1.update(plain) + s1.finalize()
        self.assertEqual(len(plain), len(cipher), "cipher and plain were not the same size!")
        '''
        Thoughts on protocol:
        - send filename, filesize, file hash in one asymm msg, which opens the prompt on the receiving end
        - receiver generates symmetric key, responds with ACK + key info, signed with receiver's private key
            - sender can use this to verify that the file will be sent to the correct receiver
        - send messagelen as first (8?) bytes of symmetric stream, then
            - client recv's messagelen
        '''
        plain2 = s2.update(cipher) + s2.finalize()
        outfile = "text/tmp.txt"
        out = open(outfile, "wb")
        out.write(plain2)
        out.close()
        self.assertEqual(get_digest(outfile), expected_hash, "beginning and ending hashes differed!")

    def test_signature(self):
        '''
        Test of verifying received signature and message, against known
        counterpart public key
        '''
        msg_orig = b'testmessageplsignore'
        msg_cipher = self.one.send_asymmetric("two@test.com",msg_orig)
        msg_plain, signature = self.two.recv_asymmetric(msg_cipher)
        self.two.verify_signature("one@test.com", msg_plain, signature)

    def test_network_sendfile(self):
        '''
        Test of (the easily testable part of) main/sendfile, which packs file
        and identity info into a JSON string, encrypts it using the specified recipient's
        public key, and signs the plaintext JSON string with the sender's private key..

        Ideally this would also test the full path (send message using socket to the recipient)
        but I am having some real trouble figuring out how to do that..
        '''
        sendfile(self.one, "two@test.com", "text/text_1k.txt", debug=True)

if __name__ == '__main__':
    unittest.main()
