from Crypto.Cipher import AES
import hashlib


class EncryptionHandler:
    def __init__(self):
        self.initializationVector = 'This is an IV456'  # 16 bytes
        self.padCharacter = '_'
        self.numberThatDoesntMatter = 696969

    def aesEncrypt(self, plaintext, key):
        aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
        offset = (16-len(plaintext) % 16)
        plaintext += (self.padCharacter * offset)
        ciphertext = aes.encrypt(plaintext)
        return ciphertext

    def aesDecrypt(self, ciphertext, key):
        aes = AES.new(key, AES.MODE_CBC, self.initializationVector)
        plaintext = aes.decrypt(ciphertext)
        plaintext = plaintext[:plaintext.find(self.padCharacter)]
        return plaintext

    def hash(self, plaintext):
        return hashlib.sha256(plaintext.encode('utf-8')).digest()
