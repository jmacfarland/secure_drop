import os
import base64
import binascii
import threading
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

def make_encryptor():
	key = os.urandom(32)
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
	return (cipher.encryptor(),
		base64.b64encode(key).decode(),
		base64.b64encode(iv).decode())

def make_decryptor(key, iv):
	cipher = Cipher(
		algorithms.AES(
			base64.b64decode(key.encode())
		),
		modes.CFB(
			base64.b64decode(iv.encode())
		)
	)
	return cipher.decryptor()
