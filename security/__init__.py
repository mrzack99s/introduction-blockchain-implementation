import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base58


class Security:
    __salt = "aabb"

    @staticmethod
    def generateRSAKey(keyword="None"):
        # Gen private key
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pri_key = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        private_key = base58.b58encode(pri_key).decode()
        public_key = base58.b58encode(
            hashlib.sha512(Security.__pubKey(privateKey=private_key_obj)).hexdigest()).decode()

        signature = Security.__getSignature(privateKey=private_key_obj,keyword=keyword)
        scriptKey = private_key + " " + base58.b58encode(signature.hex()).decode() + " " + keyword

        return scriptKey, public_key

    @staticmethod
    def getRSAPublicKey(scriptKey=None):
        scriptKey = scriptKey.split(" ")
        # Get by private key pem
        get_pri = Security.__priKey(privateKey=scriptKey[0])

        # Get public key by get prive
        pub_key = base58.b58encode(hashlib.sha512(Security.__pubKey(get_pri)).hexdigest()).decode()
        return pub_key

    @staticmethod
    def verifySignature(scriptKey=None, publicKey=None):
        scriptKey = scriptKey.split(" ")
        signature = bytes.fromhex(base58.b58decode(scriptKey[1]).decode())
        priKey = Security.__priKey(privateKey=scriptKey[0])
        pub_key_obj = Security.__pubKey(privateKey=priKey, onlyObject=True)
        pub_key = base58.b58encode(hashlib.sha512(Security.__pubKey(privateKey=priKey)).hexdigest()).decode()
        kk = pub_key_obj.verify(
            signature,
            (Security.__salt+scriptKey[2]).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )

        try:
            assert pub_key in publicKey
            assert kk is None
            return True
        except:
            return False


    @staticmethod
    def __pubKey(privateKey=None, onlyObject=False):
        public_key1 = privateKey.public_key()
        pub_key = public_key1.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key1 if onlyObject else pub_key

    @staticmethod
    def __priKey(privateKey=None):
        get_pri = serialization.load_pem_private_key(
            data=base58.b58decode(privateKey),
            password=None,
            backend=default_backend()
        )
        return get_pri

    @staticmethod
    def __getSignature(privateKey=None,keyword="None"):
        signature = privateKey.sign(
            (Security.__salt+keyword).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )

        return signature
