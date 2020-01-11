import copy
import hashlib
import json
from myBlockchain.block import Block


class myBlockchain():
    def __init__(self):
        self.__countIndex = 0
        self.__chainHash = []
        self.__chainObject = []

    def __appendBlock(self, block=None):
        self.__chainObject.append(block)
        self.__chainHash.extend({
            block.getData()["blockHash"]: block.getIndex()
        })

    def createNewBlock(self, gpsPosition=None, authorize=None):
        data = {
            "index": self.__countIndex,
            "gpsPosition": gpsPosition,
            "authorize": authorize,
            "lastBlock": None if self.__countIndex == 0 else self.__chainObject[-1]
        }

        newBlock = Block()
        newBlock.setValueBlock(data=data)

        self.__countIndex += 1
        self.__appendBlock(newBlock)

    def checkChainHaveCorrect(self):
        for count in range(1, len(self.__chainObject), 1):
            if self.__chainObject[count].getData()["prevHash"] != self.__getCheckSumHashBlock(count - 1):
                return "Have change in block " + str(count - 1)

        temp = copy.deepcopy(self.__chainObject[-1].getData())
        temp["blockHash"] = None
        checkSum = hashlib.sha512(json.dumps(temp, sort_keys=True).encode('utf-8')).hexdigest()
        if self.__chainObject[-1].getData()["blockHash"] != checkSum:
            return "Have change in block " + str(self.__chainObject[-1].getIndex())

        return "correct"

    def getChainHash(self):
        chk = self.checkChainHaveCorrect()
        ret = {
            "bool": True if chk == "correct" else False,
            "data": self.__chainHash if chk == "correct" else chk
        }

        return ret

    def getChainObject(self):
        chk = self.checkChainHaveCorrect()
        ret = {
            "bool": True if chk == "correct" else False,
            "data": self.__chainObject if chk == "correct" else chk
        }

        return ret

    def __getCheckSumHashBlock(self, index):
        return hashlib.sha512(
            json.dumps(self.__chainObject[index].getData(), sort_keys=True).encode('utf-8')).hexdigest()
