#! /usr/bin/env python3
from user import User
from main import sendfile

'''
counterpart of test2.py.
Should be run at the same time as test2, then plug in the provided
publickey to this.. HIT ENTER ON THIS ONE SECOND!
'''

def main():
    acct = User()
    acct.register("one", "one@test.com", debug=True)
    print(acct.get_pubkey_pem())
    acct.add_contact("two@test.com", input("two's pubkey: ").encode())

    sendfile(acct, "two@test.com", "text/text_1k.txt", addr="localhost", port=10000)

if __name__ == "__main__":
    main()
