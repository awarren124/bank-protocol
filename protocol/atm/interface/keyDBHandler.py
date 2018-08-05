import json
import base64


class KeyDBHandler:

    def __init__(self, fn):
        self.fileName = fn

    def writeKey(self, label, key):
        key = base64.b64encode(key)  # .decode('utf-8')
        print "Writing key: %s" % key
        with open(self.fileName) as file:
            data = json.load(file)
            data["keys"][label] = key
            print(data)
        with open(self.fileName, 'w') as file:
            json.dump(data, file, indent=4)

    def readKey(self, label):
        print('HELLO')
        with open(self.fileName) as file:
            data = json.load(file)
            key = data["keys"][label]
            print("Retrieivng key: %s" % key)
            key = base64.b64decode(key)
            return key
