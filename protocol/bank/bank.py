""" Bank Server
This module implements a bank server interface
"""

import db
import logging
from logging import info as log
import sys
import serial
import argparse
from encryptionHandler import EncryptionHandler
import os

eh = EncryptionHandler()
SPACING = '+'
PADDING = '_'


class Bank(object):
    GOOD = "O"
    BAD = "N"
    ERROR = "E"

    def __init__(self, port, baud=115200, db_path="bank.json"):
        super(Bank, self).__init__()
        self.db = db.DB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)
        self.key2 = ""

    def start(self):
        print("starting...")
        print(self.BAD)
        print(self.ERROR)
        print(self.GOOD)

        while True:
            start = self.atm.read()
            if start != "a":
                continue

            hashWord = self.atm.read(32)  # set proper length, receives the hashed version of magic word1
            aesSeed_H1 = self.atm.read(16)  # receives the first half of key2

            access_seed = self.db.get_key("AES") + aesSeed_H1  # combines both halves of key2
            self.key2 = eh.hashRaw(access_seed)  # hashes it to get the real encryption key

            verification = eh.hash(eh.aesDecrypt(self.db.get_key("magicWord1"), self.key2)) == hashWord  # decrypt the bank's copy of magic word1 and hash it, and compare it to what the atm sent over
            if not verification:  # if atm is verified continue, else end it there
                self.atm.write(self.ERROR)
                return

            pkt = self.atm.read(96)
            dec_pkt = eh.aesDecrypt(pkt, self.key2)

            command, atm_id, card_id, info, pin = dec_pkt.split(SPACING)
            print("command recieved: %s" % command)

            if command == 'w':
                amount = info
                log("Withdrawing")

                print("atm_id: %s" % atm_id)
                print("card_id: %s" % card_id)
                print("amount: %s" % amount)

                self.withdraw(atm_id, card_id, amount, pin)  # run withdraw
                self.regenerate(self, (atm_id, card_id))  # fix parameters

            elif command == 'b':
                log("Checking balance")
                # pkt = self.atm.read(72)
                # decrypt_pkt = eh.aesDecrypt(pkt, key2)
                # atm_id, card_id = struct.unpack(">36s36s", decrypt_pkt)

                atm_id = self.atm.read(48)
                card_id = self.atm.read(48)
                decrypt_atm_id = eh.aesDecrypt(atm_id,self.key2)
                decrypt_card_id = eh.aesDecrypt(card_id, self.key2)
                self.check_balance(decrypt_atm_id, decrypt_card_id)

            elif command != '':
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
        self.db.admin_set_key(store2[2],"AES")  # make sure it overrides the old key
        eh.set_IV(new_IV)  # set encryption handler with the new IV
        # enc_new_key1 = eh.RSA_encrypt(new_key1, public_key)
        enc_new_key2 = eh.RSA_encrypt(new_key2, public_key)  # encrypt keys to be sent over to the atm with RSA public key1
        enc_new_IV = eh.RSA_encrypt(new_IV, public_key)
        account_reference = self.db.get_account_reference("account1")  # gets account reference
        self.db.re_encrypt(account_reference, new_key2, self.key2)  # re-encrypts account data using new keys
        enc_magic_word1 = eh.RSA_encrypt(eh.aesDecrypt(self.db.get_key("magicWord1"), self.key2), public_key)
        enc_magic_word2 = eh.RSA_encrypt(eh.aesDecrypt(self.db.get_key("magicWord2"), self.key2), public_key)

        self.db.modify("keys", "keys", "magicWord1", new_magicWord1)  # sets the magicwords with the new ones
        self.db.modify("keys", "keys", "magicWord2", new_magicWord2)

        enc_new_magic1 = eh.RSA_encrypt(new_magicWord1, public_key)
        enc_new_magic2 = eh.RSA_encrypt(new_magicWord2, public_key)

        print("lengths in order, fill in")
        print(len(enc_new_key2))
        print(len(enc_new_IV))
        print(len(enc_new_magic1))
        print(len(enc_new_magic2))
        print(len(enc_magic_word1))
        print(len(enc_magic_word2))
        enc_pkt = "r" + enc_new_key2 + enc_new_IV + enc_new_magic1 + enc_new_magic2 + enc_magic_word1 + enc_magic_word2  # sent to atm

        key2Half = store2
        new_key1 = None
        new_key2 = None
        store2 = None
        self.atm.write(enc_pkt)
        return

    def keySplice(self, key):
        firstKey, secondKey = key[:((key) )/ 2], key[((key) / 2):]
        # re-encrypt stored stuff
        return firstKey, secondKey

    def pad_256(self, to_pad):
        offset = 256 - (to_pad % 256)
        return to_pad + offset * PADDING

    def withdraw(self, atm_id, card_id, amount, pin):  # check protocol/sequence diagram
        try:
            amount = str(amount)
            atm_id = str(atm_id)
            card_id = str(card_id)
            pin = str(pin)
        except ValueError:
            self.atm.write(self.ERROR)  # COULD BE HIJACKED
            log("Bad value sent")
            return

        public_key = self.db.get_key("RSA")  # retrieve rsa public key from database
        hashed_pin = eh.hash(pin)  # Take the card ID and pin sent from atm. Concatenate and hash to verify
        hashed_card_id = eh.hash(card_id)

        total_hash = hashed_pin + hashed_card_id
        final_hash = eh.hash(total_hash)

        enc_account_reference = self.db.get_account_reference("account1")  # gets accounts reference id
        account_reference = eh.aesDecrypt(enc_account_reference, self.key2)  # decrypt the reference and compare

        if account_reference != final_hash:  # checks to make sure the atm information matches the bank infromation
            self.atm.write(self.ERROR)  # COULD BE HIJACKED
            log("Bad card information")
            return

        enc_balance = self.db.get_balance(enc_account_reference)  # uses accounts reference id to get the balance
        balance = eh.aesDecrypt(enc_balance, self.key2)  # sets balance accordingly
        atm = self.db.get_atm(atm_id)  # change this/not sure what this is actually doing, please figure out

        print "card id: %s" % card_id
        print "checking atm: %s" % atm_id
        if atm is None:  # Figure out what this is doing
            self.atm.write(self.ERROR)  # COULD BE HIJACKED
            log("Bad ATM ID")
            return

        num_bills = self.db.get_atm_num_bills(atm_id)
        # print "checking num_bills: " + num_bills

        if num_bills is None:  # Figure out what this is doing
            self.atm.write(self.ERROR)  # COULD BE HIJACKED
            log("Bad ATM ID")
            return

        if num_bills < amount:  # Figure out what this is doing
            self.atm.write(self.ERROR)  # COULD BE HIJACKED
            log("Insufficient funds in ATM")
            return

        if balance is None:
            encrypt_bad = eh.aesEncrypt(self.BAD, self.key2)
            self.atm.write(encrypt_bad)  # COULD BE HIJACKED
            log("Bad card ID")
            return

        final_balance = balance - amount
        if final_balance >= 0:
            enc_final_balance = eh.aesEncrypt(final_balance, self.key2)
            self.db.set_balance(card_id, enc_final_balance)  # Update stored balance
            self.db.set_atm_num_bills(atm_id, num_bills - amount)  # this one probably works, but is probably insecure
            log("Valid withdrawal")

            # prepare return packet
            enc_magic2 = self.db.get_key("magicWord2")
            print "Encrypted Magic Word 2: %s" % len(enc_magic2)
            pkt = SPACING.join([self.GOOD, atm_id, card_id, amount, enc_magic2, self.key2])
            enc_pkt = eh.RSA_encrypt(pkt, public_key)
            print "length of whole packet: %s" % enc_pkt
            enc_pkt = self.pad_256(enc_pkt)
            print "length of padded packet: %s" % enc_pkt

            self.atm.write("a")
            self.atm.write(enc_pkt)  # write back to atm
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

    def spliceSecondHalf(self, string):
        return string[:len(string)/2]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", help="Serial port ATM is connected to")
    parser.add_argument("--baudrate", default=115200, help="Optional baudrate (default 115200)")
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
