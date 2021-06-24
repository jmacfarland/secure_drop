#! /usr/bin/env python3
import asyncio
import socket

class Peer():
    def __init__(self, in_addr, in_port):
        #start receiver
        self.sock_in = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_in.bind(in_addr, in_port)
        #start transmitter, don't connect until told
        self.sock_out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, out_addr, out_port):
        self.sock_out.connect(out_addr, out_port)

    def disconnect(self):
        #drop the outgoing socket, keep incoming
        self.sock_out.close()

    async def receive(self):
        return "hlasdnfjsd"

    async def _receive(self):
        while True:
            data = self.sock_in.recv(512)
            if(len(data) < 1):
                break
            print(data.decode())

    async def send(self, data):
        print("sending '{0}'".format(data))
        self.sock_out.sendall(data)

if __name__ == "__main__":
    asyncio.run(main())

async def main():
    p = Peer("localhost",10000)
    p.connect("localhost",10001)
    await p.send("hello")
