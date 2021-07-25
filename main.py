#! /usr/bin/env python3
from cryptography.fernet import InvalidToken as InvalidTokenError
from user import User
from utils import make_encryptor, make_decryptor, get_digest, _make_server_socket
import os
import sys
import json
import socket
import threading

def main():
    u = User()
    try:
        u.load_from_file()
    except InvalidTokenError:
        print("Login failed.")
        exit(0)

    cmd_loop(u)

def cmd_loop(acct):
    cmd = ''
    print("Welcome to Secure Drop, {0}".format(acct.get_name()))
    while cmd != "exit":
        cmd = input('> ').lower()
        if cmd == "help":
            print("---> add:  add a new contact")
            print("---> list: list all online contacts")
            print("---> send: send file to contact")
            print("---> receive: listen for incoming connections")
            print("---> exit: exit")
        elif cmd == "add":
            acct.add_contact(input("Contact email: "), input("Contact pubkey: "))
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
        #NOT DONE - needs to:
        #wait for recipient to respond with symmetric keyinfo
        #   verify msg signature to make sure it's the legitimate recipient
        #construct symmetric cipher
        #symmetrically encrypt file
        #send the file
    finally:
        sock.close()

def recvfile(acct, addr="localhost", port=10000):
    sock = _make_server_socket(addr, port)
    try:
        sock.listen()
        connection, client_addr = sock.accept()
        data = sock.recv(2048)
        msg, sig = acct.recv_asymmetric(data)
        print(msg)
        #NOT DONE- needs to:
        #verify the signature
        #construct a symmetric key
        #asymmetrically encrypt symmetric keyinfo
        #reply to give keyinfo to sender
        #wait for sender to respond with symmetrically encrypted file
    finally:
        sock.close()

class Server():
    '''
    I am in the process of cannibalizing this class into sendfile and recvfile
    functions.
    '''
    def __init__(self, addr="localhost", port=10000):
        print("Creating server...")
        # Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = (addr, port)
        self.sock.bind(server_address)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Done creating server")

    def execute(self):
        i = 0
        netThreads = []
        print("Listening...")
        try:
            while True:
                self.sock.listen(1)
                connection, client_address = self.sock.accept()
                netThreads.append(self.ClientThread(
                    client_address, connection))
                netThreads[i].start()
                i += 1
        finally:
            for t in netThreads:
                t.sock.close()


if __name__ == "__main__":
    main()
