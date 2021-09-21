#! /usr/bin/env python3
from user import User
from main import recvfile

'''
counterpart of test1.py.
Should be run at the same time as test1, then plug in the provided
publickey to this.. HIT ENTER ON THIS ONE FIRST!
'''

def main():
    acct = User()
    acct.register("one", "one@test.com", debug=True)
    acct.runserver('localhost', 8002)
    input("Press [ENTER] when ready...")
    acct.add_contact("one@test.com", 'localhost', 8000)

    recvfile(acct)

if __name__ == "__main__":
    main()
