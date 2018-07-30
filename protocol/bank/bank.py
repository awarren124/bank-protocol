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
            print "command recieved: " + command.encode('hex') + ""
            print("length = %s" % (len(command)))
            try:
                decrypt_instruction = eh.aesDecrypt(command, key2)[0]
            except:
                pass
            print(decrypt_instruction)
            if decrypt_instruction == 'w':
                log("Withdrawing")
                print "encrypt1"
                data = self.atm.read(80)#FLAG FOR DECODE, get pkt sent from atm, change what we actualy send
                decrypt_data = eh.aesDecrypt(data, key2)
                print "encrypt2"

                decrypt_data = decrypt_data[:-3]
                print "decrypted data: " +  decrypt_data
                print len(decrypt_data)
                atm_id, card_id, amount = struct.unpack('36s36sI', decrypt_data)
                # print "num: " + num 
                # atm_id, card_id, amount = struct.unpack(">36s36sI", decrypt_data)#unpack that and
                # withdraw(atm_id, card_id, amount)
                print "atm_id: "
                print atm_id
                print "card_id: "
                print card_id
                print "amount"
                print amount
            elif decrypt_instruction == 'b':
                log("Checking balance")
                pkt = self.atm.read(72)
                decrypt_pkt = eh.aesDecrypt(pkt, key2)
                atm_id, card_id = struct.unpack(">36s36s", decrypt_pkt)
                self.check_balance(atm_id, card_id)
            elif decrypt_instruction != '':
                self.atm.write(self.ERROR)

    def withdraw(self, atm_id, card_id, amount):
        try:
            amount = int(amount)
            atm_id = str(atm_id)
            card_id = str(card_id)
        except ValueError:
            encrypt_error = aesEncrypt(self.ERROR, key2)
            self.atm.write(encrypt_error)#COULD BE HIJACKED
            log("Bad value sent")
            return

        atm = self.db.get_atm(atm_id)
        print "card id (hex): " + card_id.encode('hex')
        print "checking atm: " + str(atm_id.encode('hex'))
        if atm is None:
            encrypt_error = aesEncrypt(self.Error,key2)
            self.atm.write(self.ERROR)#COULD BE HIJACKED
            log("Bad ATM ID")
            return

        num_bills = self.db.get_atm_num_bills(atm_id)
        # print "checking num_bills: " + num_bills

        if num_bills is None:
            encrypt_error = aesEncrypt(self.ERROR, key2)
            self.atm.write(encrypt_error)#COULD BE HIJACKED
            log("Bad ATM ID")
            return

        if num_bills < amount:
            encrypt_bad = aesEncrypt(self.Bad, key2)
            self.atm.write(encrypt_bad)#COULD BE HIJACKED
            log("Insufficient funds in ATM")
            return
        print "card id : " + card_id
        balance = self.db.get_balance(card_id)
        if balance is None:
            encrypt_bad = aesEncrypt(self.Bad, key2)
            self.atm.write(encrypt_bad)  # COULD BE HIJACKED
            log("Bad card ID")
            return

        final_amount = balance - amount
        if final_amount >= 0:
            self.db.set_balance(card_id, final_amount)#FLAG
            self.db.set_atm_num_bills(atm_id, num_bills - amount)#FLAG
            log("Valid withdrawal")
            pkt = struct.pack(">36s36sI", atm_id, card_id, amount)#figure out importance
            print "encrypt4"
            encrypt_pkt = aesEncrypt(pkt, key2)
            print "encrypt5"
            encrypt_good = aesEncrypt(self.good, key2)
            print "encrypt6"
            self.atm.write(encrypt_good)  # COULD BE HIJACKED
            print "encrypt7"
            self.atm.write(encrypt_pkt)#figure out importance
            print "encrypt8"
        else:
            encrypt_bad = aesEncrypt(self.Bad, key2)
            self.atm.write(encrypt_bad)  # COULD BE HIJACKED
            log("Insufficient funds in account")

    def check_balance(self, atm_id, card_id):
        print "checking ATM with id: " + atm_id
        if self.db.get_atm(atm_id) is None:
            self.atm.write(self.BAD)
            log("Invalid ATM ID")
            return

        balance = self.db.get_balance(str(card_id))
        if balance is None:
            self.atm.write(self.BAD)
            log("Bad card ID")
        else:
            log("Valid balance check")
            pkt = struct.pack(">36s36sI", atm_id, card_id, balance)
            self.atm.write(self.GOOD)
            self.atm.write(pkt)


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
