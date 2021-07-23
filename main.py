#! /usr/bin/env python3
from cryptography.fernet import InvalidToken as InvalidTokenError
from user import User
from session import Session
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
            print("---> exit: exit")
        elif cmd == "add":
            acct.add_contact(input("Contact name: "), input("Contact email: "))
        elif cmd == "list":
            for c in acct.contacts:
                print(c)
        elif cmd == "show":
            print(repr(acct))
    acct.save_to_file()
    exit(0)

class Client():
    def __init__(self, addr="localhost", port=10000):
        # Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = (addr, port)
        self.sock.connect(server_address)
        # setup session encryption
        self.session = Session()
        print("Attempting handshake...")
        self.handshake_client()

    def handshake_client(self):
        print("Sending client public key...")
        pubkey = self.session.send_pubkey()
        self.sock.send(pubkey)
        server_pubkey = self.sock.recv(len(pubkey))
        if self.session.recv_pubkey(server_pubkey):
            print("Handshake successful!")
        else:
            sys.exit(1)

    def send_msg(self, msg):
        print("DEBUG: Client sending the following message: %s" % msg)
        self.sock.sendall(self.session.send_msg(msg))

    def recv_msg(self, data):
        msg = self.session.recv_msg(data)
        if msg:
            print("DEBUG: Client receiving the following message:  %s" % msg)
        else:
            print("<message corrupted>")

class Server():
    def __init__(self, addr="localhost", port=10000):
        print("Creating server...")
        # Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = (addr, port)
        self.sock.bind(server_address)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Done creating server")

    class ClientThread(threading.Thread):
        def __init__(self, addr, sock):
            threading.Thread.__init__(self)
            self.sock = sock
            self.addr = addr
            self.session = Session()
            print("\nNew connection added: ", self.addr)
            print("Attempting handshake...")
            self.handshake_server()

        def handshake_server(self):
            pubkey = self.session.send_pubkey()

            # receive client's public key
            client_pubkey = self.sock.recv(len(pubkey))

            if self.session.recv_pubkey(client_pubkey):
                print("Successfully received peer public key")
            else:
                sys.exit(1)

            # send our public key
            print("Sending server public key...")
            self.sock.send(pubkey)

            print("Handshake successful!")

        def send_msg(self, msg):
            print("DEBUG: Server sending the following message: %s" % msg)
            self.sock.sendall(self.session.send_msg(msg))

        def recv_msg(self, data):
            msg = self.session.recv_msg(data)
            if msg:
                print("DEBUG: Server receiving the following message:  %s" % msg)
            else:
                print(data)
                print("<message corrupted>")

        def run(self):
            while True:
                data = self.sock.recv(256)
                if data:
                    self.recv_msg(data)


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
