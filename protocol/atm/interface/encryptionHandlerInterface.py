from Crypto.Cipher import AES
import hashlib
import os
import rsa


class EncryptionHandlerInterface:
    def __init__(self):
        self.initializationVector = os.urandom(16)  # 16 bytes
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

    def hash(self, plaintext):
        return hashlib.sha256(plaintext).hexdigest()

    def regenIV(self):
        self.initializationVector = os.urandom(16)

    def gen_key_pair(self):
        (pubkey, privkey) = rsa.newkeys(2048)
        return pubkey, privkey

    def RSA_encrypt(self, cipherText, publicKey):
        cipherText = cipherText.encode('utf-8')
        return rsa.encrypt(cipherText, publicKey)

    def RSA_decrypt(self, cipherText, privateKey):
        message = rsa.decrypt(cipherText, privateKey).decode('utf-8')
        return message