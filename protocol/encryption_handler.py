"""
Generic class that performs cryptographic operations
"""

from Crypto.Cipher import AES
import rsa
import hashlib
from constants import *


def pad_16(message):
    return message + PAD_CHAR * (16 - (len(message) % 16))


def aes_encrypt(plaintext, key, iv):  # AES encrypt
    assert(len(key) == 32)
    plaintext = pad_16(plaintext)
    aes = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = aes.encrypt(plaintext)
    return ciphertext


def aes_decrypt(ciphertext, key, iv):  # AES decrypt
    aes = AES.new(key, AES.MODE_CBC, iv)
    plaintext = aes.decrypt(ciphertext)
    return plaintext


def hash_to_hex(plaintext):
    return hashlib.sha256(plaintext).hexdigest()


def hash_to_raw(plaintext):
    return hashlib.sha256(plaintext).digest()


def gen_key_pair():
    public_key, private_key = rsa.newkeys(2048)
    public_key = public_key.save_pkcs1()
    private_key = private_key.save_pkcs1()
    return public_key, private_key


def rsa_encrypt(ciphertext, public_key):
    public_key = rsa.key.AbstractKey.load_pkcs1(public_key)
    ciphertext = ciphertext.encode('utf-8')
    return rsa.encrypt(ciphertext, public_key)


def rsa_decrypt(ciphertext, private_key):
    private_key = rsa.key.AbstractKey.load_pkcs1(private_key)
    message = rsa.decrypt(ciphertext, private_key).decode('utf-8')
    return message
