#! /usr/bin/env python3
from btpeer import BTPeer
from user import User

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

    msg_cipher = one.send("two@test.com",b'testmessage')
    msg_plain = two.receive(msg_cipher)
    print(msg_plain)



anothertest()
