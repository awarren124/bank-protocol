from encryptionHandlerInterface import EncryptionHandlerInterface
eh = EncryptionHandlerInterface()

m = "Hi my name is Bowen and I like to think about the universe"
key = "ABCDEFGHIJKLMNOP" + "A" * 16

ciphertext = eh.aesEncrypt(m, key)
print(len(ciphertext))
print ciphertext

decrypt = eh.aesDecrypt(ciphertext, key)
print(len(decrypt))
print decrypt