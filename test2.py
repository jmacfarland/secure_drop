#! /usr/bin/env python3
from user import User
from main import recvfile

def main():
    acct = User()
    acct.register("one", "one@test.com", debug=True)
    print(acct.get_pubkey_pem())
    acct.add_contact("one@test.com", input("one's pubkey: ").encode())

    recvfile(acct)

if __name__ == "__main__":
    main()
