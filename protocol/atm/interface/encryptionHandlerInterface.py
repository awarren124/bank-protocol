from Crypto.Cipher import AES
import hashlib
import os
import rsa


class EncryptionHandlerInterface:  # handles encryption
    def __init__(self):
        self.initializationVector = os.urandom(16)  # 16 bytes
        self.padCharacter = '_'
        self.numberThatDoesntMatter = 696969

    def padMult16(self, message):
        if len(message) == 16:
            return message
        print(16 - (len(message) % 16))
        return message + self.padCharacter * (16 - (len(message) % 16))

    def aesEncryptBlock(self, plaintext, key, iv=0):  # encrypt a single block
        assert(len(plaintext) == 16)
        assert(len(key) == 32)
        if iv == 0:
            iv = self.initializationVector
        aes = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = aes.encrypt(plaintext)
        return ciphertext

    def aesDecryptBlock(self, ciphertext, key, iv=0):  # decrypt a single block
        assert(len(plaintext) == 16)
        assert(len(key) == 32)
        if iv == 0:
            iv = self.initializationVector
        aes = AES.new(key, AES.MODE_CBC, iv)
        plaintext = aes.decrypt(ciphertext)
        return plaintext

    def aesEncrypt(self, plaintext, key, iv=0):  # encrypt multiple blocks
        assert(len(key) == 32)
        if iv == 0:
            iv = self.initializationVector
            plaintext = self.padMult16(plaintext)
        assert(len(plaintext) % 16 == 0)
        block = self.aesEncryptBlock(plaintext[:16:], key, iv)
        ciphertext = block
        if len(plaintext) > 16:
            ciphertext = block + self.aesEncrypt(plaintext[16::], key, iv)
        return ciphertext

    def aesDecrypt(self, ciphertext, key, iv=0):  # decrypt multiple blocks
        if iv == 0:
            iv = self.initializationVector
        dec_block = self.aesDecryptBlock(ciphertext[:16:], key, iv)
        plaintext = dec_block
        if len(ciphertext) > 16:
            plaintext = dec_block + self.aesDecrypt(ciphertext[16::], key, ciphertext[:16:])
        pad_index = plaintext.find(self.padCharacter)
        if pad_index != -1:
            plaintext = plaintext[:pad_index:]
        return plaintext

    def hash(self, plaintext):
        return hashlib.sha256(plaintext).hexdigest()

    def regenIV(self):
        self.initializationVector = os.urandom(16)

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