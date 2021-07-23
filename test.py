#! /usr/bin/env python3
from btpeer import BTPeer
from user import User
from utils import read_in_chunks
import json

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

    file = open("text/text_64k.txt", "rb")
    plain = file.read()
    cipher = one.send_symmetric(s1, plain)
    plain2 = two.recv_symmetric(s2, cipher)
    print(plain2)

test_sendfile()
