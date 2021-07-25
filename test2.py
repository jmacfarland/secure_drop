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
    print(acct.get_pubkey_pem())
    acct.add_contact("one@test.com", input("one's pubkey: ").encode())

    recvfile(acct)

if __name__ == "__main__":
    main()
