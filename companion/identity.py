#!/usr/bin/env python
from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod
from site import ENABLE_USER_SITE
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey,EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from companion.ui import UI
from companion.utils import CryptoUtils
from multiprocessing import Process, Queue
import socket
import uuid
import os
import keyring
import json
from typing import List

SERVICE_NAME="COMPENDIUM"
#PUBLIC_KEY_STORE="_PUBKEYS"
#IDX_STORE="_INDEX"
IDENTITY_KEY_PUBLIC="identity-public-key"
IDENTITY_KEY_PRIVATE="identity-private-key"
IDENTITY="identity-name"
PATH="data-path"
JSON_FILENAME="public_ids.json"

class IdentityStore(ABC):
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.SERVICE_NAME = SERVICE_NAME
        self.load()

    def get_private_key(self)->EllipticCurvePrivateKey:
        return self.private_key
    
    def get_public_key(self)->EllipticCurvePublicKey:
        return self.public_key

    def get_public_key_id(self)->str:
        return CryptoUtils.get_public_key_identifier(self.public_key)
        #IdentityStore.calculate_public_key_identifier(self.public_key)

    @abstractmethod
    def get_id(self)->str:
        pass
    
    @abstractmethod
    def get_public_identity_from_name(self, name:str)->EllipticCurvePublicKey:
        pass

    @abstractmethod        
    def get_public_identity_from_key_id(self, key_id:str)->EllipticCurvePublicKey:
        pass

    @abstractmethod
    def get_public_key_id_from_name(self, name:str)->str:
        pass 
    @abstractmethod    
    def get_public_identity_str_from_name(self, name:str)->str:
        pass
            
    @abstractmethod
    def get_public_identity_str_from_key_id(self, key_id:str)->str:
        pass

    @abstractmethod
    def set_public_identity(self, name:str, key:str)->str:
        pass
    
    @staticmethod
    def calculate_public_key_identifier(key)->str:
        if not isinstance(key,EllipticCurvePublicKey):
            temp_key = CryptoUtils.load_public_key_from_string(key)
        else:
            temp_key = key
        #temp_bytes = CryptoUtils.public_key_to_string(temp_key)
        temp_bytes = temp_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(temp_bytes)
        return hasher.finalize().hex()

    def get_identity_name(self)->str:
        q = Queue()
        p = Process(target=UI.get_user_input, args=(q,))
        p.start()
        id=q.get()
        p.join()
        return id
            
    def _generate_identity_key(self):
        print("Generating new keys")
        self.private_key = ec.generate_private_key(ec.SECP256R1)
        self.public_key = self.private_key.public_key()
        self.store()
        
    def get_public_key_encoded_str(self):
        return CryptoUtils.public_key_to_string(self.public_key)
        

    def get_private_key_encoded_str(self):
        return self.private_key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8, NoEncryption()).decode("UTF-8")
    
    def load_public_key(self, encoded_public_key:str):
        self.public_key = CryptoUtils.load_public_key_from_string(encoded_public_key)
    
    def load_private_key(self, pem_encoded_private_key:str):
        self.private_key = serialization.load_pem_private_key(pem_encoded_private_key.encode("UTF-8"),None)
    @abstractmethod
    def load(self,**kwargs):
        pass

    @abstractmethod
    def store(self,**kwargs):
        pass
    
    @abstractmethod
    def get_key_ids(self):
        pass

    @abstractmethod
    def get_key_names(self):
        pass

class StorageException(Exception):
    pass
class PublicIdentityStore(ABC):

    @abstractmethod
    def save(self):
        pass
    
    @abstractmethod
    def load(self):
        pass
    
    @abstractmethod
    def get_public_identity_str_from_name(self, name:str)->str:
        pass
        
    @abstractmethod
    def get_public_identity_str_from_key_id(self, key_id:str)->str:
        pass

    @abstractmethod
    def get_public_key_id_from_name(self, name:str)->str:
        pass

    @abstractmethod
    def set_public_identity(self, name:str, key:str)->str:
        pass
    
    @abstractmethod
    def get_key_ids(self)->List[str]:
        pass

    @abstractmethod
    def get_key_names(self)->List[str]:
        pass

    @abstractmethod
    def get_id(self)->str:
        pass
    
    @abstractmethod
    def set_id(self, name:str):
        pass


class JSONPublicIdentityStore(PublicIdentityStore):
    NAMEIDX = "names"
    KEYS = "keys"
    NAME = "id"
    
    def __init__(self, dir:str=None, full_path:str=None, json:dict=None):
        """
        If you load from json you are responsible for calling get_json and saving the
        data before the application closes
        """
        super()
        self._fullpath=None
        if(full_path is not None):
            self._fullpath = full_path
        self.path =dir
        self.data = {}
        self.loaded_json = False
        if(json is not None):
            self.data = json
            self.loaded_json = True
        self.load()

    def get_json(self):
        return self.data

    def load(self):
        if not self.loaded_json:
            if self._fullpath is None:
                self._create_path()
            if os.path.exists(self._fullpath):
                f = open(self._fullpath)
                self.data = json.load(f)
                f.close()
            else:
                self.data = {}
        save_init = False
        if not JSONPublicIdentityStore.NAMEIDX in self.data:
            self.data[JSONPublicIdentityStore.NAMEIDX]={}
            save_init=True
            
        if not JSONPublicIdentityStore.KEYS in self.data:
            self.data[JSONPublicIdentityStore.KEYS]={}
            save_init=True
        
        if save_init:
            self.save()
    
    def _create_path(self):
        os.makedirs(self.path,exist_ok=True)
        self._fullpath = self.path + JSON_FILENAME

    def save(self):
        if not self.loaded_json:
            if self._fullpath is None:
                self._create_path()

            f = open(self._fullpath,"w")
            json.dump(self.data, f, indent=2)
            f.close()

    def get_public_identity_str_from_name(self, name:str)->str:
        if name in self.data[JSONPublicIdentityStore.NAMEIDX]:
            return self.get_public_identity_str_from_key_id(self.data[JSONPublicIdentityStore.NAMEIDX][name])
        return None
    def get_public_key_id_from_name(self, name:str)->str:
        if name in self.data[JSONPublicIdentityStore.NAMEIDX]:
            return self.data[JSONPublicIdentityStore.NAMEIDX][name]
        return None
    def get_public_identity_str_from_key_id(self, key_id:str)->str:
        if key_id in self.data[JSONPublicIdentityStore.KEYS]:
            return self.data[JSONPublicIdentityStore.KEYS][key_id]
        return None

    def set_public_identity(self, name:str, key:str)->str:
        #TODO We need to handle overwrites and duplicates
        pub_key_id = CryptoUtils.get_public_key_identifier(key)
        self.data[JSONPublicIdentityStore.KEYS][pub_key_id]=key
        self.data[JSONPublicIdentityStore.NAMEIDX][name]=pub_key_id
        self.save()
    
    def get_key_ids(self):
        return self.data[JSONPublicIdentityStore.KEYS].keys()
    def get_key_names(self):
        return self.data[JSONPublicIdentityStore.NAMEIDX].keys()

    def get_id(self)->str:
        if JSONPublicIdentityStore.NAME in self.data:
            return self.data[JSONPublicIdentityStore.NAME]
        return None

    def set_id(self, name:str):
        self.data[JSONPublicIdentityStore.NAME]=name
        self.save()

        
class KeyRingIdentityStore(IdentityStore):
    def __init__(self,public_identity_store:PublicIdentityStore=None,service_name:str=None):
        super().__init__()
        self.public_id_store = public_identity_store
        if service_name is not None:
            self.SERVICE_NAME = service_name
        self._check_initialised()
    
    def get_id(self)->str:
        return self.public_id_store.get_id()

    def _check_initialised(self):
        
        if self.public_id_store is None:
            uid = keyring.get_password(self.SERVICE_NAME,PATH)
            if(uid is None):
                uid = str(uuid.uuid4())
                keyring.set_password(self.SERVICE_NAME,PATH,uid)
            path = os.path.expanduser("~/.compendium/data/"+uid + "/")
            self.public_id_store = JSONPublicIdentityStore(path)
            
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE) is None):
            self._generate_identity_key()
        else:
            self.load_private_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE))
            
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC) is None):
            self.public_key = self.private_key.public_key()
            self.store()
        else:
            self.load_public_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC))
        
        if(self.public_id_store.get_id() is None):
            self.public_id_store.set_id(self.get_identity_name())
            
            if(self.public_id_store.get_id() is None or self.public_id_store.get_id() == ""):
                self.public_id_store.set_id(socket.gethostname())
            if(self.public_id_store.get_id() is None):
                raise Exception("Unable to set device id")
            
            
    def get_public_identity_from_name(self, name:str)->EllipticCurvePublicKey:
        return self.get_public_identity_from_key_id(self.get_public_identity_str_from_name(name))
        
    def get_public_identity_from_key_id(self, key_id:str)->EllipticCurvePublicKey:
        return CryptoUtils.load_public_key_from_string(self.get_public_identity_str_from_key_id(key_id))
    
    def get_public_key_id_from_name(self, name:str)->str:
        return self.public_id_store.get_public_key_id_from_name(name)
        #return self.get_public_identity_str_from_key_id(keyring.get_password(self.SERVICE_NAME_IDX,name))
    
    def get_public_identity_str_from_name(self, name:str)->str:
        return self.public_id_store.get_public_identity_str_from_name(name)
        #return self.get_public_identity_str_from_key_id(keyring.get_password(self.SERVICE_NAME_IDX,name))
    
    def get_public_identity_str_from_key_id(self, key_id:str)->str:
        return self.public_id_store.get_public_identity_str_from_key_id(key_id)
        #return keyring.get_password(self.SERVICE_NAME_PUBLIC_KEYS,key_id)

    def set_public_identity(self, name:str, key:str)->str:
        #pub_key_id = CryptoUtils.get_public_key_identifier(key)
        #IdentityStore.calculate_public_key_identifier(key)
        self.public_id_store.set_public_identity(name,key)
        

    def store(self,**kwargs):
        keyring.set_password(self.SERVICE_NAME,IDENTITY,self.id)
        keyring.set_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE,self.get_private_key_encoded_str())
        keyring.set_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC,self.get_public_key_encoded_str())
    
    def get_key_ids(self):
        return self.public_id_store.get_key_ids()

    def get_key_names(self):
        return self.public_id_store.get_key_names()
    
    def load(self,**kwargs):
        self.id = self.id =keyring.get_password(self.SERVICE_NAME,IDENTITY)
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE) is not None):
            self.load_private_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE))
            
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC) is not None):
            self.load_public_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC))

if __name__ == "__main__":
    identity = KeyRingIdentityStore()