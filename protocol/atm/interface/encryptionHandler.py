from Crypto.Cipher import AES
import rsa
import hashlib
import os
import base64


class EncryptionHandler:
    def __init__(self):
        self.initializationVector = os.urandom(16)  # 16 bytes
        self.padCharacter = '_'
        self.numberThatDoesntMatter = 123456

    def regenIV(self):
        self.initializationVector = os.urandom(16)

    def padMult16(self, message):
        print len(message)
        print(16 - (len(message) % 16))
        return message + self.padCharacter * (16 - (len(message) % 16))

    def aesEncrypt(self, plaintext, key):  # AES encrypt
        aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
        ciphertext = aes.encrypt(plaintext)
        return ciphertext

    def aesDecrypt(self, ciphertext, key):  # AES decrypt
        aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
        plaintext = aes.decrypt(ciphertext)
        return plaintext

    def hash(self, plaintext):
        return hashlib.sha256(plaintext).hexdigest()

    def hashRaw(self, plaintext):
        return hashlib.sha256(plaintext).digest()

    def gen_key_pair(self):
        (pubkey, privkey) = rsa.newkeys(2048)
        pubkey = pubkey.save_pkcs1()
        privkey = privkey.save_pkcs1()
        return pubkey, privkey

    def RSA_encrypt(self, cipherText, publicKey):
        publicKey = rsa.key.AbstractKey.load_pkcs1(publicKey)
        cipherText = cipherText.encode('utf-8')
        return rsa.encrypt(cipherText, publicKey)

    def RSA_decrypt(self, cipherText, privateKey):
        privateKey = rsa.key.AbstractKey.load_pkcs1(privateKey)
        message = rsa.decrypt(cipherText, privateKey).decode('utf-8')
        return message
