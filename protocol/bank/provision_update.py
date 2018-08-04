from db import DB
from bank import Bank
import argparse
import serial
import struct
from encryptionHandler import EncryptionHandler

eh = EncryptionHandler()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", help="Serial port to connect to")
    parser.add_argument("--baudrate", type=int, default=115200,
                        help="Baudrate of serial port")
    parser.add_argument("--db-file", default="bank.json",
                        help="Name of bank database file")
    args = parser.parse_args()
    return args.port, args.baudrate, args.db_file


if __name__ == "__main__":
    port, baudrate, db_file = parse_args()

    atm = serial.Serial(port, baudrate, timeout=5)

    try:
        while True:
            print("Listening for provisioning info...")
            while atm.read() != "p":
                continue

            print("Reading provisioning info...")
            pkt = atm.read(48)  # receives original provision info
            card_id, pin, balance = struct.unpack(">36s8sI", pkt)

            print("Account added!")
            print()
            while atm.read() != "a":
                continue

            print("Reading provisioning info...")
            key2 = eh.hashRaw(atm.read(32))  # get correct lengths, put them here ======================================
            public_key = atm.read(2048)  # get correct lengths ======================================
            magicWord1 = atm.read(32)  # get correct lengths ======================================
            magicWord2 = atm.read(32)  # get correct lengths ======================================

            print("keys stored")
            print("Updating database...")

            db = DB(db_file)
            db.admin_create_account(pin, card_id, balance, key2)  # get pin somehow, not sure how psoc works yet, creates account
            db.admin_create_reference(pin, card_id, key2)
            print("success")
            key2 = key2[len(key2)/2:]  # cuts key2 in half to be stored
            db.admin_set_keys(key2,"AES")  # stores appropriate keys with appropriate access string in the bank database
            db.admin_set_keys(public_key, "RSA")  # ditto
            db.admin_set_keys(magicWord1, "magicWord1")  # ditto
            db.admin_set_keys(magicWord2, "magicWord2")  # ditto
            key2 = None
    except KeyboardInterrupt:
        print("Shutting down...")
