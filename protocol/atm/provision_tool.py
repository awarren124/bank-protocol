from interface.card import Card
from interface.bank import Bank
from atm import ATM
from encryptionHandler import EncryptionHandler
from interface.atm_db import DB

import argparse
import serial
import os

eh = EncryptionHandler()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("balance", type=int,
                        help="Starting balance for account")
    parser.add_argument("cport", help="Serial port to the card")
    parser.add_argument("bport", help="Serial port to the bank")
    parser.add_argument("--cbaud", type=int, default=115200,
                        help="Baudrate of serial connection to the card")
    parser.add_argument("--bbaud", type=int, default=115200,
                        help="Baudrate of serial connection to the bank")
    parser.add_argument("--pin", default="12345678",
                        help="Initial pin to program (default 12345678)")
    args = parser.parse_args()
    return args.balance, args.cport, args.bport, args.cbaud, args.bbaud, args.pin


if __name__ == "__main__":
    balance, c_port, b_port, c_baud, b_baud, pin = parse_args()

    # provision card
    print "Creating card object..."
    card = Card(c_port, baudrate=c_baud, verbose=True)
    card_id = os.urandom(18).encode("hex")
  
    print "Card object created!"

    # update bank
    print "Updating bank..."
    bank = Bank(b_port)

    # =====MARK=========#
    # bank.provision_update("c0573011d92ce40c8b5dbfa73025b352c899", pin, balance)
    print "Provisioning successful"

    key1 = os.urandom(32)  # starts by generating all keys for creation of the account, key1 used between card and atm
    key2 = os.urandom(32)  # key2 is the key specifically used btwn bank and atm

    magicWord1 = os.urandom(32)  # verification words, stored by both atm and bank upon creation
    magicWord2 = os.urandom(32)  # verification words, stored by both atm and bank upon creation

    store_keys = eh.gen_key_pair()  # RSA key pair, atm stores private, bank stores public

    magicWord1 = eh.aesEncrypt(magicWord1, key2)  # encrypt both verification words with key2
    magicWord2 = eh.aesEncrypt(magicWord2, key2)

    db = DB()  # create atm_db database object

    db.admin_set_keys(key1, "CardKey")  # stores key1 in the atm, mapped with string "CardKey" for access
    db.admin_set_keys(key2, "BankKey")  # stores key2 in the atm, mapped with string "BankKey" for access

    db.admin_set_keys(key1, "magicWord1")  # stores magicWord1 in the atm, mapped with string "magicWord1" for access
    db.admin_set_keys(key2, "magicWord2")  # stores magicWord2 in the atm, mapped with string "magicWord2" for access

    db.admin_set_keys(store_keys[0], "RSApublic")  # ditto
    db.admin_set_keys(store_keys[1], "RSAprivate")  # ditto

    print "provision lengths:"
    print "AES key 2 length: %s" % len(str(key2))
    print "RSA private key length: %s" % len(str(store_keys[1]))
    print "Magic word 1 length: %s" % len(str(magicWord1))
    print "Magic word 2 length: %s" % len(str(magicWord2))
    bank.provision_key(key2, store_keys[0], magicWord1, magicWord2)  # run provision key in /atm/interface/bank,
    print"keys sent"

    if card.provision(card_id, pin, key1, magicWord1):  # for general purposes, ignore
        print "Card provisioned!"

        # update bank
        print "Updating bank..."
        bank = Bank(b_port)
        bank.provision_update(card_id, pin, balance)
        print "Provisioning successful"
    else:
        print "Card already provisioned!"

