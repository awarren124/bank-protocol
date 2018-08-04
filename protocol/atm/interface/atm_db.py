""" DB
This module implements an interface to the bank_server database.
"""

import json
import os.path
import base64


class ATM_DB(object):
    """Implements a Database interface for the bank server and admin interface"""
    def __init__(self, db_path="atmcontents.json"):
        self.path = db_path

        try:
            with open(db_path, "r") as f:
                d = f.read()
            with open(db_path + ".bak", "w") as f:
                f.write(d)
        except:
            pass

    def close(self):
        """close the database connection"""
        pass

    def init_db(self):
        """initialize database with file at filepath"""
        with open(self.path, 'w') as f:
            f.write(json.dumps({'keys': {}}))

    def exists(self):
        return os.path.exists(self.path)

    def modify(self, table, k, subks, vs):
        if not self.exists():
            self.init_db()
        with open(self.path, 'r') as f:
            db = json.loads(f.read())

        try:
            for subk, v in zip(subks, vs):
                if k not in db[table]:
                    db[table][k] = {}
                db[table][k][subk] = v
        except KeyboardInterrupt:
            return False

        with open(self.path, 'w') as f:
            f.write(json.dumps(db))

        return True

    def read(self, table, k, subk):
        with open(self.path, 'r') as f:
            db = json.loads(f.read())

        try:
            print "table: " + table
            print "k: " + k
            print "subk: " + subk
            print db[table]
            print db[table][k]
            print db[table][k][subk]
            return db[table][k][subk]
        except KeyError:
            return None

    ############################
    # BANK INTERFACE FUNCTIONS #
    ############################


    '''
    def set_balance(self, card_id, balance):
        """set balance of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["bal"], [balance])

    def get_balance(self, card_id):
        """get balance of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return self.read("cards", card_id, "bal")

    def get_atm(self, atm_id):
        """get atm_id of atm: atm_id
        this is an obviously dumb function but maybe it can be expanded...

        Returns:
            (string or None): Returns atm_id on Success. None otherwise.
        """
        return 1000
        if self.get_atm_num_bills(atm_id):
            return atm_id
        return None
    '''

    '''
    def get_atm_num_bills(self, atm_id):
        """get number of bills in atm: atm_id

        Returns:
            (string or None): Returns num_bills on Success. None otherwise.
        """
        return 1000
        print "reading from json with atm_id: " + atm_id
        return self.read("atms", atm_id, "nbills")

    def set_atm_num_bills(self, atm_id, num_bills):
        """set number of bills in atm: atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return True
        return self.modify("atms", atm_id, ["nbills"], [num_bills])
    '''
    #############################
    # ADMIN INTERFACE FUNCTIONS #
    #############################
    '''
    def admin_create_account(self, card_id, amount):
        """create account with account_name, card_id, and amount

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        hashed_atm_id = hash(atm_id)
        hashed_card_id = hash(card_id)
        total_hash = hashed_atm_id + hashed_card_id
        final_hash = hash(total_hash)
        return self.modify('account', final_hash, ["bal"], [amount])

    def admin_create_atm(self, atm_id):
        """create atm with atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """

        return self.modify("atms", atm_id, ["nbills"], [128])

    def admin_get_balance(self, card_id):
        """get balance of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return self.read("cards", card_id, "bal")

    def admin_set_balance(self, card_id, balance):
        """set balance of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["bal"], [balance])
    '''

    def admin_set_key(self, key, label):
        # magic is just used to look up the key
        if label[:3:] != 'RSA':  # RSA Keys don't need base64 encoding
            key = base64.b64encode(key)
        return self.modify("keys", label, ["val"], [key])

    def admin_get_key(self, label):
        key = self.read("keys", label, "val")
        if label[:3:] == 'RSA':
            return key
        return base64.b64decode(key)

