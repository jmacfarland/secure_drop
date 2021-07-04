#! /usr/bin/env python3
from btpeer import BTPeer

def test():
    p = BTPeer(5, 10001)
    p.addpeer("test2",'localhost',10000)
    p.sendtopeer("test2",'MESG', b'Hello! This is a test')

test()
