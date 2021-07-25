import os
import base64
import binascii
import threading
import hashlib
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def make_session_id():
	return binascii.b2a_hex(os.urandom(8))

def thread_debug(msg):
	# """ Prints a messsage to the screen with the name of the current thread """
	print("[%s] %s" % ( str(threading.currentThread().getName()), msg ))

def read_in_chunks(file_object, chunk_size=1024):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

def make_encryptor(key=None, iv=None):
	#MAKE NEW ENCRYPTOR
	#returns:
	#	- encryptor object
	#	- key
	#	- IV
	if not key:
		key = os.urandom(32)
	if not iv:
		iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
	return (cipher.encryptor(),
		base64.b64encode(key).decode(),
		base64.b64encode(iv).decode())

def make_decryptor(key=None, iv=None):
	#MAKE NEW DECRYPTOR
	#returns:
	#	- decryptor object
	#	- key
	#	- IV
	if not key:
		key = os.urandom(32)
	if not iv:
		iv = os.urandom(16)
	cipher = Cipher(
		algorithms.AES(
			base64.b64decode(key.encode())
		),
		modes.CFB(
			base64.b64decode(iv.encode())
		)
	)
	return cipher.decryptor(), key, iv

def get_digest(file_path):
    h = hashlib.sha256()

    with open(file_path, 'rb') as file:
        while True:
            # Reading is buffered, so we can read smaller chunks.
            chunk = file.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)
        file.close()
    return h.hexdigest()

def _make_server_socket(addr="localhost", port=10000):
	print("Creating server...")
	# Create a TCP/IP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Bind the socket to the port
	server_address = (addr, port)
	sock.bind(server_address)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	print("Done creating server")
	return sock
