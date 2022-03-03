#!/usr/bin/env python
from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey,EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization 
from companion.ui import UI
from multiprocessing import Process, Queue
import socket

import keyring

SERVICE_NAME="COMPENDIUM"
IDENTITY_KEY_PUBLIC="identity-public-key"
IDENTITY_KEY_PRIVATE="identity-private-key"
IDENTITY="identity-name"

class IdentityStore(ABC):
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.id = None
        self.SERVICE_NAME = SERVICE_NAME
        self.load()

    def get_private_key(self)->EllipticCurvePrivateKey:
        return self.private_key
    
    def get_public_key(self)->EllipticCurvePublicKey:
        return self.public_key

    def get_id(self)->str:
        return self.id
    
    @abstractmethod
    def get_public_identity(self, name:str)->EllipticCurvePublicKey:
        pass

    @abstractmethod
    def get_public_identity_str(self, name:str)->str:
        pass

    @abstractmethod
    def set_public_identity(self, name:str, key:str)->str:
        pass
    
    def get_identity_name(self):
        q = Queue()
        p = Process(target=UI.get_user_input, args=(q,))
        p.start()
        self.id=q.get()
        p.join()
            
    def _generate_identity_key(self):
        print("Generating new keys")
        self.private_key = ec.generate_private_key(ec.SECP256R1)
        self.public_key = self.private_key.public_key()
        self.store()
        
    def get_public_key_encoded_str(self):
        return self.public_key.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode("UTF-8")

    def get_private_key_encoded_str(self):
        return self.private_key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8, NoEncryption()).decode("UTF-8")
    
    def load_public_key(self, pem_encoded_public_key:str):
        self.public_key = serialization.load_pem_public_key(pem_encoded_public_key.encode("UTF-8"))
    
    def load_private_key(self, pem_encoded_private_key:str):
        self.private_key = serialization.load_pem_private_key(pem_encoded_private_key.encode("UTF-8"),None)
    @abstractmethod
    def load(self,**kwargs):
        pass

    @abstractmethod
    def store(self,**kwargs):
        pass

class KeyRingIdentityStore(IdentityStore):
    def __init__(self,service_name:str=None):
        super().__init__()
        if service_name is not None:
            self.SERVICE_NAME = service_name
        self._check_initialised()
    
    def _check_initialised(self):
        self.id =keyring.get_password(self.SERVICE_NAME,IDENTITY)
        if(self.id is None):
            self.get_identity_name()
            
            if(self.id is None or self.id == ""):
                self.id = socket.gethostname()
            if(self.id is None):
                raise Exception("Unable to set device id")
            keyring.set_password(self.SERVICE_NAME,IDENTITY,self.id)
        
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE) is None):
            self._generate_identity_key()
        else:
            self.load_private_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE))
            
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC) is None):
            self.public_key = self.private_key.public_key()
            self.store()
        else:
            self.load_public_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC))
            
    def get_public_identity(self, name:str)->EllipticCurvePublicKey:
        return serialization.load_pem_public_key(keyring.get_password(self.SERVICE_NAME,name).encode("UTF-8"))
    
    def get_public_identity_str(self, name:str)->str:
        return keyring.get_password(self.SERVICE_NAME,name)

    def set_public_identity(self, name:str, key:str)->str:
        keyring.set_password(self.SERVICE_NAME,name,key)

    def store(self,**kwargs):
        keyring.set_password(self.SERVICE_NAME,IDENTITY,self.id)
        keyring.set_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE,self.get_private_key_encoded_str())
        keyring.set_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC,self.get_public_key_encoded_str())
    
    def load(self,**kwargs):
        self.id = self.id =keyring.get_password(self.SERVICE_NAME,IDENTITY)
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE) is not None):
            self.load_private_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE))
            
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC) is not None):
            self.load_public_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC))

if __name__ == "__main__":
    identity = KeyRingIdentityStore()