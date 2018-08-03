""" Bank Server
This module implements a bank server interface
"""

import uuid
import db
import logging
from logging import info as log
import sys
import serial
import argparse
import struct
from encryptionHandler import EncryptionHandler
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib
import os

eh = EncryptionHandler()
# accessKey2 = eh.hash(key2)


class Bank(object):
    GOOD = "O"
    BAD = "N"
    ERROR = "E"
    key2 = ''  # make sure global variable is secure


    def __init__(self, port, baud=115200, db_path="bank.json"):
        super(Bank, self).__init__()
        self.db = db.DB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)

    def start(self):
        print("starting...")
        print(self.BAD)
        print(self.ERROR)
        print(self.GOOD)
        while True:
            hashWord = self.atm.read()  # set proper length, receives the hashed version of magic word1
            firstHalf = self.atm.read(16)# receives the first half of key2
            accessKey = firstHalf + self.db.get_key("AES")  # combines both halves of key2
            self.key2 = hash(accessKey)  # hashes it to get the real encryption key

            verification = eh.hash(eh.aesDecrypt(self.db.get_key("magicWord1"), accessKey)) == hashWord  # decrypt the bank's copy of magic word1 and hash it, and compare it to what the atm sent over
            if not verification:  # if atm is verified continue, else end it there
                self.atm.write(self.ERROR)
                return
            command = self.atm.read(16)  # FLAG FOR DECODE, receives command from atm to decide what to do
            # if len(command) != 0:
            print("command recieved: " + command.encode('hex') + "")
            print("length = %s" % (len(command)))
            decrypt_instruction = None
            try:
                decrypt_instruction = eh.aesDecrypt(command, self.key2)[0]#???? decrypts command
                print(decrypt_instruction)
            except:
                pass
            if decrypt_instruction == 'w':
                log("Withdrawing")
                print("encrypt1")
                # data = self.atm.read(80)#FLAG FOR DECODE, get pkt sent from atm, change what we actualy send
                # decrypt_data = eh.aesDecrypt(data, key2)
                print("encrypt2")

                # decrypt_data = decrypt_data[:-3]
                # print "decrypted data: " +  decrypt_data
                # print len(decrypt_data)
                # atm_id, card_id, amount = struct.unpack('36s36sI', decrypt_data)
                atm_id = self.atm.read(48)
                card_id = self.atm.read(48)
                amount = self.atm.read(16)
                pin = self.atm.read() # PlEASE ADD PIN SENDING FROM THE CARD============================================================================================
                decrypt_atm_id = eh.aesDecrypt(atm_id,self.key2)  # use key2 to decrypt al of the information
                decrypt_card_id = eh.aesDecrypt(card_id, self.key2)
                decrypt_amount = eh.aesDecrypt(amount, self.key2)
                decrypt_pin = eh.aesDecrypt(pin, self.key2)
                # print "num: " + num
                # atm_id, card_id, amount = struct.unpack(">36s36sI", decrypt_data)#unpack that and
                print("decrypt_atm_id: ")
                print(decrypt_atm_id)
                print("decrypt_card_id: ")
                print(decrypt_card_id)
                print("decrypt_amount")
                print(decrypt_amount)
                self.withdraw(decrypt_atm_id, decrypt_card_id, decrypt_amount, decrypt_pin)#run withdraw
                self.regenerate(self,(decrypt_atm_id, decrypt_card_id))
            elif decrypt_instruction == 'b':
                log("Checking balance")
                # pkt = self.atm.read(72)
                # decrypt_pkt = eh.aesDecrypt(pkt, key2)
                # atm_id, card_id = struct.unpack(">36s36s", decrypt_pkt)

                atm_id = self.atm.read(48)
                card_id = self.atm.read(48)
                decrypt_atm_id = eh.aesDecrypt(atm_id,self.key2)
                decrypt_card_id = eh.aesDecrypt(card_id, self.key2)
                self.check_balance(decrypt_atm_id, decrypt_card_id)
            elif decrypt_instruction != '':
                self.atm.write(self.ERROR)

    def regenerate(self, atm_id, card_id):  # check protocol diagram, will fix sometime
        try:
            atm_id = str(atm_id)
            card_id = str(card_id)
        except ValueError:
            encrypt_error = eh.aesEncrypt(self.ERROR, self.key2)
            self.atm.write(encrypt_error)  # COULD BE HIJACKED
            log("Bad value sent")
            return
        public_key = self.db.get_key("RSA")
        # new_key1 = os.urandom(32)
        new_key2 = os.urandom(32)  # generates new keys, magicwords, and initialization vector
        new_magicWord1 = os.urandom(32)
        new_magicWord2 = os.urandom(32)
        new_IV = os.urandom(16)
        # store1 = keySplice(new_key1)
        store2 = self.keySplice(new_key2)  # splits key
        self.db.admin_set_keys(store2[2],"AES")  # make sure it overrides the old key
        eh.set_IV(new_IV)  # set encryption handler with the new IV
        # enc_new_key1 = eh.RSA_encrypt(new_key1, public_key)
        enc_new_key2 = eh.RSA_encrypt(new_key2, public_key)  # encrypt keys to be sent over to the atm with RSA public key1
        enc_new_IV = eh.RSA_encrypt(new_IV, public_key)
        account_reference = self.db.get_account_id("access")  # gets account reference
        self.db.re_encrypt(account_reference, new_key2, self.key2)  # re-encrypts account data using new keys
        enc_magic_word1 = eh.RSA_encrypt(eh.aesDecrypt(self.db.get_key("magicWord1"), self.key2), public_key)
        enc_magic_word2 = eh.RSA_encrypt(eh.aesDecrypt(self.db.get_key("magicWord2"), self.key2), public_key)
        self.db.modify("key", "magicWord1", "key", new_magicWord1)  # sets the magicwords with the new ones
        self.db.modify("key", "magicWord2", "key", new_magicWord2)
        enc_new_magic1 = eh.RSA_encrypt(new_magicWord1, public_key)
        enc_new_magic2 = eh.RSA_encrypt(new_magicWord2, public_key)
        print("lengths in order, fill in")
        print(len(enc_new_key2))
        print(len(enc_new_IV))
        print(len(enc_new_magic1))
        print(len(enc_new_magic2))
        print(len(enc_magic_word1))
        print(len(enc_magic_word2))
        enc_pkg = "r" + enc_new_key2 + enc_new_IV + enc_new_magic1 + enc_new_magic2 + enc_magic_word1 + enc_magic_word2#sent to atm
        #key1Half = store1[2]
        key2Half = store2[2]
        new_key1 = None
        new_key2 = None
        store1 = None
        store2 = None
        self.serial.write(enc_pkg)
        return

    def combine(self, keyHalf1, keyHalf2):
        return hash(keyHalf1 + keyHalf2)

    def keySplice(self, key):
        firstKey, secondKey = key[:((key) )/ 2], key[((key) / 2):]
        #re-encrypt stored stuff
        return ("", firstKey, secondKey)

    def withdraw(self, atm_id, card_id, amount, pin):#check protocol/sequence diagram
        try:
            amount = int(amount)
            atm_id = str(atm_id)
            card_id = str(card_id)
            pin = int(pin)
        except ValueError:
            encrypt_error = eh.aesEncrypt(self.ERROR, self.db)
            self.atm.write(encrypt_error)  # COULD BE HIJACKED
            log("Bad value sent")
            return
        public_key = self.db.get_key("RSA")  # retrieve rsa public key from database
        hashed_pin = hash(pin)  # take the card, pin sent from atm, and concatenate and hash to verify it is the real info
        hashed_card_id = hash(card_id)
        total_hash = hashed_pin + hashed_card_id
        final_hash = hash(total_hash)
        enc_account_reference = self.db.get_account_id("access")  # gets accounts reference id
        account_reference = eh.aesDecrypt(enc_account_reference, self.key2)  # decrypt the reference and compare
        balance = 0
        if account_reference != final_hash:  # checks to make sure the atm information, matches the actual matches the actual bank infromation
            encrypt_error = eh.aesEncrypt(self.Error, self.key2)
            self.atm.write(self.ERROR)  # COULD BE HIJACKED
            log("bad information")
            return
        enc_balance = self.db.get_balance(enc_account_reference)  # uses accounts reference id to get the balance
        balance = eh.aesDecrypt(enc_balance, self.key2)  # sets balance accordingly
        atm = self.db.get_atm(atm_id)  # change this/not sure what this is actually doing, please figure out
        print "card id (hex): " + card_id.encode('hex')
        print "checking atm: " + str(atm_id.encode('hex'))
        if atm is None:  # Figure out what this is doing
            encrypt_error = eh.aesEncrypt(self.Error,self.key2)
            self.atm.write(self.ERROR)# COULD BE HIJACKED
            log("Bad ATM ID")
            return

        num_bills = self.db.get_atm_num_bills(atm_id)
        # print "checking num_bills: " + num_bills

        if num_bills is None:# Figure out what this is doing
            encrypt_error = eh.aesEncrypt(self.ERROR, self.key2)
            self.atm.write(encrypt_error)# COULD BE HIJACKED
            log("Bad ATM ID")
            return

        if num_bills < amount:# Figure out what this is doing
            encrypt_bad = eh.aesEncrypt(self.BAD, self.key2)
            self.atm.write(encrypt_bad)# COULD BE HIJACKED
            log("Insufficient funds in ATM")
            return
        print "card id : " + card_id
        # balance = self.db.get_balance(card_id)
        if balance is None:
            encrypt_bad = eh.aesEncrypt(self.BAD, self.key2)
            self.atm.write(encrypt_bad)  # COULD BE HIJACKED
            log("Bad card ID")
            return

        final_amount = balance - amount
        if final_amount >= 0:
            self.db.set_balance(card_id, final_amount)  # Fix this function, shouldn't work, make sure there is encryption
            self.db.set_atm_num_bills(atm_id, num_bills - amount)  # this one proabably works, but is probably insecure
            log("Valid withdrawal")
            # pkt = struct.pack(">36s36sI", atm_id, card_id, amount)#figure out importance
            print "encrypt4"
            # encrypt_pkt = eh.aesEncrypt(pkt, key2)
            print "encrypt5"
            print "encrypt6"
            # self.atm.write(encrypt_good)  # COULD BE HIJACKED
            print "encrypt7"
            # print len(encrypt_good)
            # self.atm.write(encrypt_pkt)#figure out importance
            # print len(encrypt_pkt)
            good = 'O'
            encPacket = ''
            publicKey = self.db.get_key("RSA")
            enc_good = eh.RSA_encrypt(good, public_key)  # encrypt with RSA public key amd send values back, sends good value to tell atm to spit money
            enc_atm= eh.RSA_encrypt(str(atm_id), public_key)
            enc_card= eh.RSA_encrypt(str(card_id), public_key)
            enc_amount= eh.RSA_encrypt(str(amount), public_key)
            enc_magic = eh.RSA_encrypt(eh.aesDecrypt(self.db.get_key("magiWord2"), self.key2), public_key)  # sends magicWord2 which is verification that this was sent from the actual bank
            print "encrypted lengths"
            print len(enc_good)
            print "atm:"
            print len(enc_atm)
            print "card:"
            print len(enc_card)
            print "amount:"
            print len(enc_amount)
            print "magic Word"
            print len(enc_magic)
            encPacket = "a" + enc_good + enc_atm + enc_card + enc_amount +enc_magic
            print "encrypt8 (the important once)"

            self.atm.write(encPacket)  # send back to atm
            self.regenerate(atm_id, card_id)  # not finished implementing, may be done in the morning
        else:
            encrypt_bad = eh.aesEncrypt(self.BAD, self.key2)
            self.atm.write(encrypt_bad)  # COULD BE HIJACKED
            log("Insufficient funds in account")

    def check_balance(self, atm_id, card_id):
        print "checking ATM with id: " + atm_id
        if self.db.get_atm(atm_id) is None:
            encrypt_bad = eh.aesEncrypt(self.BAD, self.key2)
            packet = "a" + encrypt_bad
            self.atm.write(packet)
            log("Invalid ATM ID")
            return

        balance = self.db.get_balance(str(card_id))
        if balance is None:
            encrypt_bad = eh.aesEncrypt(self.BAD, self.key2)
            packet = "a" + encrypt_bad
            self.atm.write(packet)
            log("Bad card ID")
        else:
            log("Valid balance check")
            # pkt = struct.pack(">36s36sI", atm_id, card_id, balance)
            encrypt_good = eh.aesEncrypt(self.GOOD, self.key2)
            print len(encrypt_good)
            encrypt_atm_id = eh.aesEncrypt(atm_id, self.key2)
            print len(encrypt_atm_id)
            encrypt_card_id = eh.aesEncrypt(card_id, self.key2)
            print len(encrypt_card_id)
            encrypt_balance = eh.aesEncrypt(str(balance), self.key2)
            print len(encrypt_balance)
            packet = "a" + encrypt_good + encrypt_atm_id + encrypt_card_id + encrypt_balance
            self.atm.write(packet)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", help="Serial port ATM is connected to")
    parser.add_argument("--baudrate", help="Optional baudrate (default 115200)")
    return parser.parse_args()


def main():
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)
    log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(log_format)
    log.addHandler(ch)

    args = parse_args()

    bank = Bank(args.port, args.baudrate)
    try:
        bank.start()
    except KeyboardInterrupt:
        print "Shutting down bank..."


if __name__ == "__main__":
    main()
