from interface.card import Card
from interface.bank import Bank
from atm import ATM
from os import urandom
from encryptionHandler import EncryptionHandler
eh = EncryptionHandler()
import argparse
import serial


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
    print "Provisioning card..."
    card = Card(c_port, baudrate=c_baud, verbose=True)
    uuid = urandom(18).encode("hex")
  
    print "Card provisioned!"

    # update bank
    print "Updating bank..."
    bank = Bank(b_port)
    bank.provision_update("c0573011d92ce40c8b5dbfa73025b352c899", pin, balance)
    print "Provisioning successful"
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    magicWord1 = os.urandom(32)
    magicWord2 = os.urandom(32)
    store_keys = eh.gen_key_pair()
    magicWord1 = eh.aesEncrypt(magicWord1, key2)
    magicWord2 = eh.aesEncrypt(magicWord2, key2)
    bank.provision_key(key1, key2, store_keys[0], store_keys[1], magicword1, magicWord2)
    print"keys sent"
    if card.provision(uuid, pin):
        print "Card provisioned!"

        # update bank
        print "Updating bank..."
        bank = Bank(b_port)
        bank.provision_update(uuid, pin, balance)
        print "Provisioning successful"
    else:
        print "Card already provisioned!"

