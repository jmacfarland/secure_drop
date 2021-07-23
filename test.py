#! /usr/bin/env python3
from btpeer import BTPeer
from user import User
#from utils import read_in_chunks
import json
import hashlib

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

def test():
    p = BTPeer(5, 10001,myid="one@one.com")
    p.addpeer("two",'localhost',10000)
    p.begin_session_with("two")
    p.send_cipher_message("two", "This should be encrypted!")

def anothertest():
    one = User()
    one.register("one", "one@test.com", debug=True)

    two = User()
    two.register("two", "two@test.com", debug=True)
    pubkey_one = one.get_pubkey_pem()
    two.add_contact("one@test.com", pubkey_one)

    pubkey_two = two.get_pubkey_pem()
    one.add_contact("two@test.com", pubkey_two)

    msg = b'test'*100
    msg_cipher = one.send_asymmetric("two@test.com",msg)
    msg_plain = two.recv_asymmetric(msg_cipher)

def test_symmetric():
    one = User()
    one.register("one", "one@test.com", debug=True)

    two = User()
    two.register("two", "two@test.com", debug=True)
    pubkey_one = one.get_pubkey_pem()
    two.add_contact("one@test.com", pubkey_one)

    pubkey_two = two.get_pubkey_pem()
    one.add_contact("two@test.com", pubkey_two)

    s1, key1, iv1 = one._make_encryptor_session()
    ct = one.send_asymmetric("two@test.com",
        json.dumps({"key":key1, "iv":iv1}).encode()
    )

    pt = two.recv_asymmetric(ct)
    data = json.loads(pt.decode())
    s2 = two._make_decryptor_session(data['key'], data['iv'])

    msg_cipher = one.send_symmetric(s1, b'a secret message '*4096)
    print(two.recv_symmetric(s2, msg_cipher))

def test_sendfile():
    one = User()
    one.register("one", "one@test.com", debug=True)

    two = User()
    two.register("two", "two@test.com", debug=True)
    pubkey_one = one.get_pubkey_pem()
    two.add_contact("one@test.com", pubkey_one)

    pubkey_two = two.get_pubkey_pem()
    one.add_contact("two@test.com", pubkey_two)

    s1, key1, iv1 = one._make_encryptor_session()
    ct = one.send_asymmetric("two@test.com",
        json.dumps({"key":key1, "iv":iv1}).encode()
    )

    pt = two.recv_asymmetric(ct)
    data = json.loads(pt.decode())
    s2 = two._make_decryptor_session(data['key'], data['iv'])

    #########################
    testfile = "text/text_64k.txt"
    file = open(testfile, "rb")
    plain = file.read()
    file.close()
    print("size of plain file:      {0}".format(len(plain)))
    print("hash of plain file:      {0}".format(get_digest(testfile)))
    cipher = one.send_symmetric(s1, plain)
    print("size of encrypted file:  {0}".format(len(cipher)))
    '''
    Thoughts on protocol:
    - send filename, filesize, file hash in one asymm msg, which opens the prompt on the receiving end
    - receiver send back ACK w/ symmetric key
    - send messagelen as first (8?) bytes of symmetric stream, then
        - client recv's messagelen
    '''
    plain2 = two.recv_symmetric(s2, cipher)
    print("size of recv plain:      {0}".format(len(plain2)))
    outfile = "text/tmp.txt"
    out = open(outfile, "wb")
    out.write(plain2)
    out.close()
    print("hash of recvd file:      {0}".format(get_digest(outfile)))

test_sendfile()
