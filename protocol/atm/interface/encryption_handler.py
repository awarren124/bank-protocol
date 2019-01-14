"""
Generic class that performs cryptographic operations
"""

from Crypto.Cipher import AES
import rsa
import hashlib
import os


class EncryptionHandler:
    def __init__(self):
        self.iv = os.urandom(16)  # 16 bytes
        self.pad_char = '_'

    def regenerate_iv(self):
        self.iv = os.urandom(16)

    def pad_16(self, message):
        return message + self.pad_char * (16 - (len(message) % 16))

    def aes_encrypt(self, plaintext, key):  # AES encrypt
        assert(len(key) == 32)
        plaintext = self.pad_16(plaintext)
        aes = AES.new(key, AES.MODE_CBC, self.iv)
        ciphertext = aes.encrypt(plaintext)
        return ciphertext

    def aes_decrypt(self, ciphertext, key):  # AES decrypt
        aes = AES.new(key, AES.MODE_CBC, self.iv)
        plaintext = aes.decrypt(ciphertext)
        return plaintext

    def hash_to_hex(self, plaintext):
        return hashlib.sha256(plaintext).hexdigest()

    def hash_to_raw(self, plaintext):
        return hashlib.sha256(plaintext).digest()

    def gen_key_pair(self):
        public_key, private_key = rsa.newkeys(2048)
        public_key = public_key.save_pkcs1()
        private_key = private_key.save_pkcs1()
        return public_key, private_key

    def rsa_encrypt(self, ciphertext, public_key):
        public_key = rsa.key.AbstractKey.load_pkcs1(public_key)
        ciphertext = ciphertext.encode('utf-8')
        return rsa.encrypt(ciphertext, public_key)

    def rsa_decrypt(self, ciphertext, private_key):
        private_key = rsa.key.AbstractKey.load_pkcs1(private_key)
        message = rsa.decrypt(ciphertext, private_key).decode('utf-8')
        return message
