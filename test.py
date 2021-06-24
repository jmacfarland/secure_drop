#! /usr/bin/env python3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
import socket
import sys
import threading
from main import Client, Server
from session import Session

def test1():
    privkey = Ed25519PrivateKey.generate()
    raw_bytes = privkey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    b64_bytes = base64.b64encode(raw_bytes)
    print(b64_bytes.decode())

    bytes = base64.b64decode(b64_bytes)

    key2 = Ed25519PrivateKey.from_private_bytes(bytes)


def test2():
    s = Server()
    s.execute()

test2()
