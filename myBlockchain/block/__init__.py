import copy
import hashlib
import datetime
import json
import base58
from security import Security


class Block():
    def __init__(self):
        self.__index = 0
        self.__timestamp = None
        self.__authorize = None
        self.__data = {
            "prevHash": None,
            "blockHash": None,
            "gpsPosition": None
        }

    def setValueBlock(self, data=None):
        self.__index = data["index"]
        self.__timestamp = datetime.datetime.now()
        self.__data["gpsPosition"] = base58.b58encode(json.dumps(data["gpsPosition"]).encode('utf-8')).decode()
        self.__authorize = data["authorize"]
        if data["lastBlock"] is None:
            self.__generatePrevHash()
        else:
            self.__generatePrevHash(data["lastBlock"].getData())
        self.__generateBlockHash()
        jsonData = json.dumps(self.__data, sort_keys=True).encode('utf-8')
        self.__data = base58.b58encode(jsonData)

    def __generateBlockHash(self):
        self.__data["blockHash"] = hashlib.sha512(json.dumps(self.__data, sort_keys=True).encode('utf-8')).hexdigest()

    def __generatePrevHash(self, lastBlockData=None):
        if lastBlockData is None:
            self.__data["prevHash"] = hashlib.sha512(
                hashlib.sha512(json.dumps(lastBlockData, sort_keys=True).encode('utf-8')).hexdigest().encode(
                    'utf-8')).hexdigest()
        else:
            self.__data["prevHash"] = hashlib.sha512(
                json.dumps(lastBlockData, sort_keys=True).encode('utf-8')).hexdigest()

    def setGpsPosition(self, gpsPosition=None):
        self.__data["gpsPosition"] = gpsPosition

    def getIndex(self):
        return self.__index

    def getTimestamp(self):
        return self.__timestamp

    def getData(self):
        temp = base58.b58decode(self.__data)
        jsonData = json.loads(temp)
        return jsonData

    def getBlockData(self,privateKey=None):
        if Security.verifySignature(privateKey=privateKey,publicKey=self.__authorize):
            temp = base58.b58decode(copy.deepcopy(self.__data))
            jsonData = json.loads(temp)
            jsonData["gpsPosition"] = base58.b58decode(jsonData["gpsPosition"]).decode()

            return jsonData

        return ""
