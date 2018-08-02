from db import DB
from bank import Bank
import argparse
import serial
import struct


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
            print "Listening for provisioning info..."
            while atm.read() != "p":
                continue

            print "Reading provisioning info..."
            pkt = atm.read(48)
            uuid, pin, balance = struct.unpack(">36s8sI", pkt)

            print "Updating database..."
            db = DB(db_file)
            db.admin_create_account(uuid, balance)
            print "Account added!"
            print
            while atm.read() != "a":
                continue

            print "Reading provisioning info..."
            key2 = atm.read()#get correct lengths
            public_key = atm.read()#get correct lengths
            magicWord1 = atm.read()#get correct lengths
            magicWord2 = atm.read()#get correct lengths
            db.admin_set_keys(key2, "AES")
            db.admin_set_keys(public_key, "RSA")
            db.admin.set_keys(magicWord1, "magicWord1")
            db.admin.set_keys(magicWord2, "magicWord2")
            print("keys stored")
            print "Updating database..."

    except KeyboardInterrupt:
        print "Shutting down..."
