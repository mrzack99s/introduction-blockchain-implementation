import copy
import hashlib
import datetime
import json
import base58
from security import Security


class Block():
    def __init__(self):
        self.__index = 0,
        self.__header = {
            "prevHash": None,
            "blockHash": None,
            "timestamp": None,
            "authorize": None
        }
        self.__data = {
            "gpsPosition": None
        }

    def setGpsPosition(self, gpsPosition=None):
        temp = base58.b58decode(self.__data)
        data = json.loads(temp)
        data["gpsPosition"] = json.dumps(gpsPosition)
        jsonData = json.dumps(data, sort_keys=True).encode('utf-8')
        self.__data = base58.b58encode(jsonData)

    def setValueBlock(self, data=None):
        self.__index = data["index"]
        self.__header["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.__data["gpsPosition"] = base58.b58encode(json.dumps(data["gpsPosition"]).encode('utf-8')).decode()
        self.__header["authorize"] = data["authorize"]

        if data["lastBlock"] is None:
            self.__generatePrevHash()
        else:
            self.__generatePrevHash(data["lastBlock"].getData())
        self.__generateBlockHash()
        jsonData = json.dumps(self.__data, sort_keys=True).encode('utf-8')
        self.__data = base58.b58encode(jsonData)

    def __generateBlockHash(self):
        hashData = {
            "index": self.__index,
            "header": self.__header,
            "data": self.__data
        }
        self.__header["blockHash"] = hashlib.sha512(json.dumps(hashData, sort_keys=True).encode('utf-8')).hexdigest()

    def __generatePrevHash(self, lastBlockData=None):
        if lastBlockData is None:
            self.__header["prevHash"] = hashlib.sha512(
                hashlib.sha512(json.dumps(lastBlockData, sort_keys=True).encode('utf-8')).hexdigest().encode(
                    'utf-8')).hexdigest()
        else:
            self.__header["prevHash"] = hashlib.sha512(
                json.dumps(lastBlockData, sort_keys=True).encode('utf-8')).hexdigest()

    def getIndex(self):
        return self.__index

    def getData(self):
        temp = base58.b58decode(self.__data)
        jsonData = json.loads(temp)
        retData = {
            "index": self.__index,
            "header": self.__header,
            "data": jsonData
        }


        return retData

    def getBlockData(self, scriptKey=None):
        if Security.verifySignature(scriptKey=scriptKey, publicKey=self.__header["authorize"]):
            temp = base58.b58decode(copy.deepcopy(self.__data))
            jsonData = json.loads(temp)
            jsonData["gpsPosition"] = base58.b58decode(jsonData["gpsPosition"]).decode()

            retData = {
                "index": self.__index,
                "header": self.__header,
                "data": jsonData
            }

            return retData

        return ""
