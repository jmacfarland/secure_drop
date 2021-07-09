#! /usr/bin/env python3
from btpeer import BTPeer

def test():
    p = BTPeer(5, 10001,myid="one@one.com")
    p.addpeer("two",'localhost',10000)
    p.begin_session_with("two")
    p.send_cipher_message("two", "This should be encrypted!")

test()
