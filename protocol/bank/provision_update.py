from bank_db import bankDB
from bank import Bank
import argparse
import serial
import struct
from encryption_handler import EncryptionHandler

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
        print "Listening for provisioning info..."
        while atm.read() != "p":
            continue

        print "Reading provisioning info..."
        pkt = atm.read(48)  # receives original provision info
        card_id, pin, balance = struct.unpack(">36s8sI", pkt)

        print "Account added!"
        print ""
        while atm.read() != "a":
            continue

        print "Reading provisioning info..."
        key2 = eh.hash_to_raw(atm.read(32))
        public_key = atm.read(426)  # likely variable length
        magic_word_1 = atm.read(32)
        magic_word_2 = atm.read(32)

        print "Keys received"
        print "Updating database..."

        db = bankDB(db_file)
        db.admin_create_account(pin, card_id, balance, key2)  # creates account
        db.admin_create_reference(pin, card_id, key2)
        print "success"

        key2 = key2[len(key2)/2:]  # cuts key2 in half to be stored

        # stores keys with appropriate access string in the bank database
        db.admin_set_key(key2, "AES")
        db.admin_set_key(public_key, "RSA")

        db.admin_set_key(magic_word_1, "magicWord1")
        db.admin_set_key(magic_word_2, "magicWord2")

        key2 = None

    except KeyboardInterrupt:
        print "Shutting down..."
