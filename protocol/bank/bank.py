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
key1 = b'\xe6R|\x84x\xce\x96\xa5T\xac\xd8l\xd0\xe4Lf\xf6&\x16E\xfa/\x9b\xa2\xea!\xceY\x85\xbe\ra'
key2 = b'\xb5\xd2\x03v\xad)\xd5\x8a \xa6\xa0_\x94^\xe6X=$&|&\xd4c*#M\xee[\tl\xfc\xd0'

eh = EncryptionHandler()
# accessKey2 = eh.hash(key2)


class Bank(object):
    GOOD = "O"
    BAD = "N"
    ERROR = "E"

    def __init__(self, port, baud=115200, db_path="bank.json"):
        super(Bank, self).__init__()
        self.db = db.DB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)

    def start(self):
        print "starting..."
        print self.BAD
        print self.ERROR
        print self.GOOD
        while True:
            command = self.atm.read(16)#FLAG FOR DECODE, receives command from atm to decide what to do
            # if len(command) != 0:
            print "command recieved: " + command.encode('hex') + ""
            print("length = %s" % (len(command)))
            decrypt_instruction = None
            try:
                decrypt_instruction = eh.aesDecrypt(command, key2)[0]
                print decrypt_instruction
            except:
                pass
            if decrypt_instruction == 'w':
                log("Withdrawing")
                print "encrypt1"
                # data = self.atm.read(80)#FLAG FOR DECODE, get pkt sent from atm, change what we actualy send
                # decrypt_data = eh.aesDecrypt(data, key2)
                print "encrypt2"

                # decrypt_data = decrypt_data[:-3]
                # print "decrypted data: " +  decrypt_data
                # print len(decrypt_data)
                #atm_id, card_id, amount = struct.unpack('36s36sI', decrypt_data)
                atm_id = self.atm.read(48)
                card_id = self.atm.read(48)
                amount = self.atm.read(16)
                decrypt_atm_id = eh.aesDecrypt(atm_id,key2)
                decrypt_card_id = eh.aesDecrypt(card_id, key2)
                decrypt_amount = eh.aesDecrypt(amount, key2)
                # print "num: " + num 
                # atm_id, card_id, amount = struct.unpack(">36s36sI", decrypt_data)#unpack that and
                print "decrypt_atm_id: "
                print decrypt_atm_id
                print "decrypt_card_id: "
                print decrypt_card_id
                print "decrypt_amount"
                print decrypt_amount
                self.withdraw(decrypt_atm_id, decrypt_card_id, decrypt_amount)
                #self.regenerate(self,(decrypt_atm_id, decrypt_card_id)
            elif decrypt_instruction == 'b':
                log("Checking balance")
                # pkt = self.atm.read(72)
                # decrypt_pkt = eh.aesDecrypt(pkt, key2)
                # atm_id, card_id = struct.unpack(">36s36s", decrypt_pkt)

                atm_id = self.atm.read(48)
                card_id = self.atm.read(48)
                decrypt_atm_id = eh.aesDecrypt(atm_id,key2)
                decrypt_card_id = eh.aesDecrypt(card_id, key2)
                self.check_balance(decrypt_atm_id, decrypt_card_id)
            elif decrypt_instruction != '':
                self.atm.write(self.ERROR)

    def regenerate(self, atm_id, card_id):
        try:
            atm_id = str(atm_id)
            card_id = str(card_id)
        except ValueError:
            encrypt_error = eh.aesEncrypt(self.ERROR, key2)
            self.atm.write(encrypt_error)#COULD BE HIJACKED
            log("Bad value sent")
            return
        new_key1 = os.urandom(32)
        new_key2 = os.urandom(32)
        new_IV = os.urandom(16)
        store1 = keySplice(new_key1)
        store2 = keySplice(new_key2)
        enc_new_key1 = eh.aesEncrypt(new_key1, key2)
        enc_new_key2 = eh.aesEncrypt(new_key2, key2)
        enc_new_IV = eh.aesEncrypt(new_IV, key2)
        enc_AtmId = eh.aesEncrypt(str(atm_id), key2)
        enc_CardId = eh.aesEncrypt(str(card_id), key2)
        enc_pkg = "a" + enc_AtmId + enc_CardId + enc_new_key1 + enc_new_key2 + enc_new_IV
        key1Half = store1[2]
        key2Half = store2[2]
        store1 = None
        store2 = None
        self.serial.write(enc_pkg)
        return

    def combine(self, keyHalf1, keyHalf2):
        return hash(keyHalf1 + keyHalf2)

    def keySplice(self, key):
        firstKey, secondKey = key[:((key) )/ 2], key[((key) / 2):]
        #re-encrypt stored stuff
        return (hashKey, firstKey, secondKey)




    def withdraw(self, atm_id, card_id, amount):
        try:
            amount = int(amount)
            atm_id = str(atm_id)
            card_id = str(card_id)
        except ValueError:
            encrypt_error = eh.aesEncrypt(self.ERROR, key2)
            self.atm.write(encrypt_error)#COULD BE HIJACKED
            log("Bad value sent")
            return


        atm = self.db.get_atm(atm_id)
        print "card id (hex): " + card_id.encode('hex')
        print "checking atm: " + str(atm_id.encode('hex'))
        if atm is None:
            encrypt_error = eh.aesEncrypt(self.Error,key2)
            self.atm.write(self.ERROR)#COULD BE HIJACKED
            log("Bad ATM ID")
            return

        num_bills = self.db.get_atm_num_bills(atm_id)
        # print "checking num_bills: " + num_bills

        if num_bills is None:
            encrypt_error = eh.aesEncrypt(self.ERROR, key2)
            self.atm.write(encrypt_error)#COULD BE HIJACKED
            log("Bad ATM ID")
            return

        if num_bills < amount:
            encrypt_bad = aesEncrypt(self.BAD, key2)
            self.atm.write(encrypt_bad)#COULD BE HIJACKED
            log("Insufficient funds in ATM")
            return
        print "card id : " + card_id
        balance = self.db.get_balance(card_id)
        if balance is None:
            encrypt_bad = eh.aesEncrypt(self.BAD, key2)
            self.atm.write(encrypt_bad)  # COULD BE HIJACKED
            log("Bad card ID")
            return

        final_amount = balance - amount
        if final_amount >= 0:
            self.db.set_balance(card_id, final_amount)#FLAG
            self.db.set_atm_num_bills(atm_id, num_bills - amount)#FLAG
            log("Valid withdrawal")
            # pkt = struct.pack(">36s36sI", atm_id, card_id, amount)#figure out importance
            encAtmId = eh.aesEncrypt(str(atm_id), key2)
            encCardId = eh.aesEncrypt(str(card_id), key2)
            encAmount = eh.aesEncrypt(str(amount), key2)
            print "encrypt4"
            # encrypt_pkt = eh.aesEncrypt(pkt, key2)
            print "encrypt5"
            encrypt_good = eh.aesEncrypt(self.GOOD, key2)
            print "encrypt6"
            # self.atm.write(encrypt_good)  # COULD BE HIJACKED
            print "encrypt7"
            # print len(encrypt_good)
            # self.atm.write(encrypt_pkt)#figure out importance
            # print len(encrypt_pkt)

            encPacket = "a" + encrypt_good + str(encAtmId) + str(encCardId) + str(encAmount)
            print "encrypt8 (the important once)"

            print str(encrypt_good)
            print str(encAtmId)
            print str(encCardId)
            print str(encAmount)
            self.atm.write(encPacket)
        else:
            encrypt_bad = eh.aesEncrypt(self.BAD, key2)
            self.atm.write(encrypt_bad)  # COULD BE HIJACKED
            log("Insufficient funds in account")

    def check_balance(self, atm_id, card_id):
        print "checking ATM with id: " + atm_id
        if self.db.get_atm(atm_id) is None:
            encrypt_bad = eh.aesEncrypt(self.BAD, key2)
            packet = "a" + encrypt_bad
            self.atm.write(packet)
            log("Invalid ATM ID")
            return

        balance = self.db.get_balance(str(card_id))
        if balance is None:
            encrypt_bad = eh.aesEncrypt(self.BAD, key2)
            packet = "a" + encrypt_bad
            self.atm.write(packet)
            log("Bad card ID")
        else:
            log("Valid balance check")
            # pkt = struct.pack(">36s36sI", atm_id, card_id, balance)
            encrypt_good = eh.aesEncrypt(self.GOOD, key2)
            print len(encrypt_good)
            encrypt_atm_id = eh.aesEncrypt(atm_id, key2)
            print len(encrypt_atm_id)
            encrypt_card_id = eh.aesEncrypt(card_id, key2)
            print len(encrypt_card_id)
            encrypt_balance = eh.aesEncrypt(str(balance), key2)
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
