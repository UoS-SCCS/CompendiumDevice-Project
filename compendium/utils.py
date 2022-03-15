from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey,EllipticCurvePrivateKey
import base64
PEM_HEAD = "-----BEGIN PUBLIC KEY-----";
PEM_TAIL = "-----END PUBLIC KEY-----";

class SigningKey(ABC):
    pass

class VerificationKey(ABC):
    pass

class IdentitySigningKey(SigningKey):
    pass

class IdentityVerificationKey(SigningKey):
    pass

class CryptoUtils():
    @staticmethod
    def load_public_key_from_string(public_key_str):
        if public_key_str.startswith(PEM_HEAD):
            return serialization.load_pem_public_key(public_key_str.encode("UTF-8"))
        else:
            return serialization.load_der_public_key(B64.decode(public_key_str))
    
    def public_key_to_string(public_key):
        return B64.encode(public_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo))


    @staticmethod
    def get_public_key_identifier(key)->str:
        if not isinstance(key,EllipticCurvePublicKey):
            temp_key = CryptoUtils.load_public_key_from_string(key)
        else:
            temp_key = key
        #temp_bytes = CryptoUtils.public_key_to_string(temp_key)
        temp_bytes = temp_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(temp_bytes)
        return hasher.finalize().hex()


class B64():
    @staticmethod
    def encode(data:bytes)->str:
        return base64.b64encode(data).decode("UTF-8")
    
    @staticmethod
    def decode(b64string:str)->bytes:
        return base64.decodebytes(b64string.encode("UTF-8"))
