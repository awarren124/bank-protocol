from Crypto.Cipher import AES
import hashlib
import os


class EncryptionHandlerCard:
    def __init__(self):
        self.initializationVector = os.urandom(16)  # 16
        self.padCharacter = '_'
        self.numberThatDoesntMatter = 696969

    def aesEncrypt(self, plaintext, key):
        aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
        offset = (16 - (len(plaintext) % 16))
        plaintext += (self.padCharacter * offset)
        ciphertext = aes.encrypt(plaintext)
        return ciphertext

    def aesDecrypt(self, ciphertext, key):
        aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
        plaintext = aes.decrypt(ciphertext)
        plaintext = plaintext[:plaintext.find(self.padCharacter)]
        return plaintext

    @staticmethod
    def hash(self, plaintext):
        return hashlib.sha256(plaintext).hexdigest()

    def regenIV(self):
        self.initializationVector = os.urandom(16)
