import json
import base64


class AtmDBHandler:

    def __init__(self, fn):
        self.fileName = fn

    def writeKey(self, label, key):
        key = base64.b64encode(key)
        with open(self.fileName) as file:
            data = json.load(file)
            data["keys"][label] = key
        with open(self.fileName, 'w') as file:
            json.dump(data, file)

    def readKey(self, label):
        with open(self.fileName) as file:
            data = json.load(file)
            key = data["keys"][label]
            key = base64.b64decode(key)
            return key
