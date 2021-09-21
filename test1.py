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
    acct.runserver('localhost', 8000)
    acct.add_contact("two@test.com", "localhost", 8002)
    input("Press [ENTER] when ready...")

    sendfile(acct, "two@test.com", "text/text_1k.txt", addr='localhost', port=10001)

if __name__ == "__main__":
    main()
