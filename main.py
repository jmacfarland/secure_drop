#! /usr/bin/env python3
from cryptography.fernet import InvalidToken as InvalidTokenError
from user import User
from utils import make_encryptor, make_decryptor, get_digest, get_digest_no_read, _make_server_socket, thread_debug
import os
import sys
import json
import socket

def main():
    u = User()
    try:
        u.load_from_file()
    except InvalidTokenError:
        print("Login failed.")
        exit(0)

    #drop to user command loop
    u.runserver('localhost', 8000)
    cmd_loop(u)

def cmd_loop(acct):
    cmd = ''
    print("Welcome to Secure Drop, {0}".format(acct.fullname))
    while cmd != "exit":
        cmd = input('> ').lower()
        if cmd == "help":
            print("---> add:  add a new contact")
            print("---> list: list all online contacts")
            print("---> send: send file to contact")
            print("---> receive: listen for incoming connections")
            print("---> exit: exit")
        elif cmd == "add":
            acct.add_contact(input("Contact email: "), input("Contact server address: "), input("Contact server port: "))
        elif cmd == "list":
            for c in acct.contacts:
                print(c)
        elif cmd == "send":
            recipient = input("File recipient: ")
            if not (recipient in acct.contacts):
                print("Error: recipient not in contacts")
                continue
            else:
                filename = input("Filename: ")
                try:
                    sendfile(acct, recipient, file)
                except:
                    pass
        elif cmd == "show":
            print(acct.get_pubkey_pem())
            print(" ")
            print(acct.__repr__())
    acct.save_to_file()
    exit(0)

def sendfile(acct, recipient, file, addr=None, port=None, debug=False):
    '''
    Send recipient an encrypted file...
    '''
    pt = json.dumps({
        "peer":acct.email, #sender's email so recipient can look up our pubkey
        "file":file.split("/")[-1], #get filename without path
        "hash":get_digest(file), #send filehash so recipient can verify the integrity of downloaded file
        "size":os.path.getsize(file) #filesize so recipient can simply sock.recv(size)...
        #because len(plain_file) == len(symmetrically_encrypted_file)
    }).encode()
    ct = acct.send_asymmetric(recipient,pt) #construct asymmetric message to recipient
    if debug: #dumps pt/ct and skips trying to send the file over the network
        print("PLAINTEXT:   {0}".format(pt))
        print("CIPHERTEXT:  {0}".format(ct))
        return

    if not addr:
        addr = input("host: ")
    if not port:
        port = int(input("port: "))
    try:
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = (addr, port)
        sock.connect(server_address)
        sock.sendall(ct)

        #wait for recipient to respond with symmetric keyinfo
        data = json.loads(
            sock.recv(2048).decode()
        )
        print(data)


        #construct symmetric cipher
        enc, _, _ = make_encryptor(data['key'], data['iv'])

        #symmetrically encrypt file
        file = open(file, "rb")
        file_pt = file.read()
        file.close()
        file_ct = enc.update(file_pt) + enc.finalize()

        #send the file
        sock.sendall(file_ct)
    finally:
        sock.close()

def recvfile(acct, addr="localhost", port=10000):
    sock = _make_server_socket(addr, port)
    try:
        sock.listen()
        connection, client_addr = sock.accept()
        print(client_addr)
        data = connection.recv(2048)
        msg, sig = acct.recv_asymmetric(data)
        metadata = json.loads(msg.decode())
        print(metadata)
        #NOT DONE- needs to:
        #verify the signature
        #construct a symmetric key
        dec, key, iv = make_decryptor()

        #asymmetrically encrypt symmetric keyinfo
        keyinfo_pt = json.dumps({
            "key": key,
            "iv": iv
        }).encode()
        keyinfo_ct = acct.send_asymmetric(
            email=metadata['peer'],
            message=keyinfo_pt
        )

        #reply to give keyinfo to sender
        connection.sendall(keyinfo_pt)

        #wait for sender to respond with symmetrically encrypted file
        buffer = b''
        while True:
            data = connection.recv(2048)
            if not data:
                break
            buffer += data

        #decrypt file
        pt = dec.update(buffer) + dec.finalize()
        if metadata['hash'] != get_digest_no_read(pt):
            print("File hashes did not match! discarding")
        else:
            print(pt)
    finally:
        sock.close()

if __name__ == "__main__":
    main()
