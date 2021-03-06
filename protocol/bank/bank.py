""" Bank Server
This module implements a bank server interface
"""

import bank_db
import logging
from logging import info as log
from encryption_handler import EncryptionHandler
from ..constants import *

import os
import sys
import serial
import argparse

eh = EncryptionHandler()


class Bank(object):

    def __init__(self, port, baud=115200, db_path="bank.json"):
        self.db = bank_db.bankDB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)
        self.key2 = ""

    def start(self):
        print "Starting bank..."
        while True:
            start = self.atm.read()
            if start != "a":
                continue

            hashed_magic_word_1 = self.atm.read(32)  # set proper length, receives the hashed version of magic word1
            key2_seed_first_half = self.atm.read(16)  # receives the first half of key2

            access_seed = self.db.get_key("AES") + key2_seed_first_half  # combines both halves of key2
            self.key2 = eh.hash_to_raw(access_seed)  # hashes it to get the real encryption key

            verification = eh.hash_to_hex(eh.aes_decrypt(self.db.get_key("magicWord1"), self.key2)) == hashed_magic_word_1  # verify
            if not verification:  # if atm is verified continue, else end it there
                self.atm.write(ERROR)
                return

            pkt = self.atm.read(96)
            dec_pkt = eh.aes_decrypt(pkt, self.key2)

            command, atm_id, card_id, info, pin = dec_pkt.split(SPACE_CHAR)
            print "command recieved: %s" % command

            if command == WITHDRAW:  # WITHDRAW
                amount = info
                log("Withdrawing")

                print "atm_id: %s" % atm_id
                print "card_id: %s" % card_id
                print "amount: %s" % amount

                self.withdraw(atm_id, card_id, amount, pin)  # run withdraw
                self.regenerate(self, (atm_id, card_id))  # fix parameters

            elif command == CHECK_BALANCE:  # CHECK BALANCE
                log("Checking balance")
                # pkt = self.atm.read(72)
                # decrypt_pkt = eh.aesDecrypt(pkt, key2)
                # atm_id, card_id = struct.unpack(">36s36s", decrypt_pkt)

                atm_id = self.atm.read(48)
                card_id = self.atm.read(48)
                decrypt_atm_id = eh.aes_decrypt(atm_id, self.key2)
                decrypt_card_id = eh.aes_decrypt(card_id, self.key2)
                self.check_balance(decrypt_atm_id, decrypt_card_id)

            elif command != '':
                self.atm.write(ERROR)

    def regenerate(self, atm_id, card_id):  # check protocol diagram, will fix sometime
        try:
            atm_id = str(atm_id)
            card_id = str(card_id)
        except ValueError:
            encrypt_error = eh.aes_encrypt(ERROR, self.key2)
            self.atm.write(encrypt_error)  # COULD BE HIJACKED
            log("Bad value sent")
            return
        public_key = self.db.get_key("RSA")
        # new_key1 = os.urandom(32)

        new_key2 = os.urandom(32)  # generates new keys, magicwords, and initialization vector
        new_magic_word_1 = os.urandom(32)
        new_magic_word_2 = os.urandom(32)
        new_iv = os.urandom(16)

        # store1 = keySplice(new_key1)
        store2 = self.split_key(new_key2)  # splits key
        self.db.admin_set_key(store2[2], "AES")  # make sure it overrides the old key
        eh.iv = new_iv  # set encryption handler with the new IV
        # enc_new_key1 = eh.RSA_encrypt(new_key1, public_key)
        enc_new_key2 = eh.rsa_encrypt(new_key2, public_key)  # encrypt keys to be sent over to the atm with RSA public key1
        enc_new_iv = eh.rsa_encrypt(new_iv, public_key)

        account_reference = self.db.get_account_reference("account1")  # gets account reference
        self.db.re_encrypt(account_reference, new_key2, self.key2)  # re-encrypts account data using new keys
        enc_magic_word_1 = eh.rsa_encrypt(eh.aes_decrypt(self.db.get_key("magicWord1"), self.key2), public_key)
        enc_magic_word_2 = eh.rsa_encrypt(eh.aes_decrypt(self.db.get_key("magicWord2"), self.key2), public_key)

        self.db.modify("keys", "keys", "magicWord1", new_magic_word_1)  # sets the magicwords with the new ones
        self.db.modify("keys", "keys", "magicWord2", new_magic_word_2)

        enc_new_magic_1 = eh.rsa_encrypt(new_magic_word_1, public_key)
        enc_new_magic_2 = eh.rsa_encrypt(new_magic_word_2, public_key)

        print "length of encoded new key 2: %s" % len(enc_new_key2)
        print "length of encoded new iv: %s" % len(enc_new_iv)
        print "length of encoded new magic word 1: %s" % len(enc_new_magic_1)
        print "length of encoded new magic word 2: %s" % len(enc_new_magic_2)
        print "length of encoded old magic word 1: %s" % len(enc_magic_word_1)
        print "length of encoded old magic word 2: %s" % len(enc_magic_word_2)
        enc_pkt = "r" + enc_new_key2 + enc_new_iv + enc_new_magic_1 + enc_new_magic_2 + enc_magic_word_1 + enc_magic_word_2  # sent to atm

        key2Half = store2
        new_key1 = None
        new_key2 = None
        store2 = None

        self.atm.write(enc_pkt)
        return

    def split_key(self, key):
        first_key, second_key = key[:len(key) / 2], key[len(key) / 2:]
        # re-encrypt stored stuff
        return first_key, second_key

    def pad_256(self, to_pad):
        offset = 256 - (to_pad % 256)
        return to_pad + offset * PAD_CHAR

    def withdraw(self, atm_id, card_id, amount, pin):  # check protocol/sequence diagram
        try:
            amount = str(amount)
            atm_id = str(atm_id)
            card_id = str(card_id)
            pin = str(pin)
        except ValueError:
            self.atm.write(ERROR)  # COULD BE HIJACKED
            log("Bad value sent")
            return

        public_key = self.db.get_key("RSA")  # retrieve rsa public key from database
        hashed_pin = eh.hash_to_hex(pin)  # Take the card ID and pin sent from atm. Concatenate and hash to verify
        hashed_card_id = eh.hash_to_hex(card_id)

        total_hash = hashed_pin + hashed_card_id
        final_hash = eh.hash_to_hex(total_hash)

        enc_account_reference = self.db.get_account_reference("account1")  # gets accounts reference id
        account_reference = eh.aes_decrypt(enc_account_reference, self.key2)  # decrypt the reference and compare

        if account_reference != final_hash:  # checks to make sure the atm information matches the bank infromation
            self.atm.write(ERROR)  # COULD BE HIJACKED
            log("Bad card information")
            return

        enc_balance = self.db.get_balance(enc_account_reference)  # uses accounts reference id to get the balance
        balance = eh.aes_decrypt(enc_balance, self.key2)  # sets balance accordingly
        atm = self.db.get_atm(atm_id)  # change this/not sure what this is actually doing, please figure out

        print "card id: %s" % card_id
        print "checking atm: %s" % atm_id
        if atm is None:  # Figure out what this is doing
            self.atm.write(ERROR)  # COULD BE HIJACKED
            log("Bad ATM ID")
            return

        num_bills = self.db.get_atm_num_bills(atm_id)
        # print "checking num_bills: " + num_bills

        if num_bills is None:  # Figure out what this is doing
            self.atm.write(ERROR)  # COULD BE HIJACKED
            log("Bad ATM ID")
            return

        if num_bills < amount:  # Figure out what this is doing
            self.atm.write(ERROR)  # COULD BE HIJACKED
            log("Insufficient funds in ATM")
            return

        if balance is None:
            encrypt_bad = eh.aes_encrypt(BAD, self.key2)
            self.atm.write(encrypt_bad)  # COULD BE HIJACKED
            log("Bad card ID")
            return

        final_balance = balance - amount
        if final_balance >= 0:
            enc_final_balance = eh.aes_encrypt(final_balance, self.key2)
            self.db.set_balance(card_id, enc_final_balance)  # Update stored balance
            self.db.set_atm_num_bills(atm_id, num_bills - amount)  # this one probably works, but is probably insecure
            log("Valid withdrawal")

            # prepare return packet
            enc_magic2 = self.db.get_key("magicWord2")
            print "Encrypted Magic Word 2: %s" % len(enc_magic2)
            pkt = SPACE_CHAR.join([GOOD, atm_id, card_id, amount, enc_magic2, self.key2])
            enc_pkt = eh.rsa_encrypt(pkt, public_key)
            print "length of whole packet: %s" % enc_pkt
            enc_pkt = self.pad_256(enc_pkt)
            print "length of padded packet: %s" % enc_pkt

            self.atm.write("a")
            self.atm.write(enc_pkt)  # write back to atm
            self.regenerate(atm_id, card_id)  # not finished implementing, may be done in the morning

        else:
            encrypt_bad = eh.aes_encrypt(BAD, self.key2)
            self.atm.write(encrypt_bad)  # COULD BE HIJACKED
            log("Insufficient funds in account")

    def check_balance(self, atm_id, card_id):
        print "checking ATM with id: " + atm_id
        if self.db.get_atm(atm_id) is None:
            encrypt_bad = eh.aes_encrypt(BAD, self.key2)
            packet = "a" + encrypt_bad
            self.atm.write(packet)
            log("Invalid ATM ID")
            return

        balance = self.db.get_balance(str(card_id))
        if balance is None:
            encrypt_bad = eh.aes_encrypt(BAD, self.key2)
            packet = "a" + encrypt_bad
            self.atm.write(packet)
            log("Bad card ID")
        else:
            log("Valid balance check")
            # pkt = struct.pack(">36s36sI", atm_id, card_id, balance)
            encrypt_good = eh.aes_encrypt(GOOD, self.key2)
            print "Length of encrypted GOOD: %s " % len(encrypt_good)
            encrypt_atm_id = eh.aes_encrypt(atm_id, self.key2)
            print "Length of encrypted ATM ID: %s" % len(encrypt_atm_id)
            encrypt_card_id = eh.aes_encrypt(card_id, self.key2)
            print "Length of encrypted card ID: %s" % len(encrypt_card_id)
            encrypt_balance = eh.aes_encrypt(str(balance), self.key2)
            print "Length of encrypted balance: %s" % len(encrypt_balance)
            packet = "a" + encrypt_good + encrypt_atm_id + encrypt_card_id + encrypt_balance
            self.atm.write(packet)

    def split_second_half(self, string):
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
