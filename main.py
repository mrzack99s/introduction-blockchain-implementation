import json

from myBlockchain import myBlockchain
from flask import Flask, request
from flask_cors import CORS
from security import Security

chain = myBlockchain()

app = Flask(__name__)
# Enable CORS
CORS(app)


@app.route("/getChain", methods=["GET"])
def getChain():
    global chain
    ret = []
    myChain = chain.getChainObject()
    if myChain["bool"]:
        for x in myChain["data"]:
            s = {
                "index": x.getIndex(),
                "prevHash": x.getData()["prevHash"],
                "blockHash": x.getData()["blockHash"],
                "gpsPosition": x.getData()["gpsPosition"]
            }
            ret.append(s)
    else:
        return str(myChain["data"])

    return json.dumps(ret)


@app.route("/createBlock", methods=["POST"])
def createBlock():
    global chain
    data = json.loads(request.data)
    chain.createNewBlock(gpsPosition=data["gpsPosition"],authorize=data["authorize"])
    return json.dumps(chain.getChainObject()["data"][-1].getData())


@app.route("/generateKey", methods=["POST"])
def generateKey():
    data = json.loads(request.data)
    scriptKey, public_key = Security.generateRSAKey(keyword=data["keyword"])
    ret = {
        "scriptKey": scriptKey,
        "publicKey": public_key
    }
    return json.dumps(ret)


@app.route("/getBlockData", methods=["POST"])
def getBlockData():
    global chain
    data = json.loads(request.data)
    scriptKey = data["scriptKey"]
    try:
        chainHash = chain.getChainHash()["data"]
        index = chainHash.index(data["blockHash"])
        block = chain.getChainObject()["data"][index]
    except:
        block = chain.getChainObject()["data"][int(data["index"])]

    ret = block.getBlockData(scriptKey=scriptKey)
    return json.dumps(ret)


@app.route("/getPublicKey", methods=["POST"])
def getPublicKey():
    data = json.loads(request.data)
    ret = {
        "publicKey": Security.getRSAPublicKey(scriptKey=data["scriptKey"])
    }
    return json.dumps(ret)


@app.route("/setGpsPosition", methods=["POST"])
def setGpsPosition():
    global chain
    data = json.loads(request.data)
    block = chain.getChainObject()["data"][int(data["index"])]
    block.setGpsPosition(gpsPosition=data["gpsPosition"])
    return json.dumps(block.getData())


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=1234)
