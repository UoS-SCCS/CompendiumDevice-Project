"""
 © Copyright 2021-2022 University of Surrey

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""
#!/usr/bin/env python
import json
import os
import socket
import uuid
from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod
from multiprocessing import Process, Queue
from site import ENABLE_USER_SITE
from typing import List

import keyring
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          PublicFormat)

from compendium.ui import UI
from compendium.utils import CryptoUtils

#Constants for key storage fields
SERVICE_NAME="COMPENDIUM"
IDENTITY_KEY_PUBLIC="identity-public-key"
IDENTITY_KEY_PRIVATE="identity-private-key"
PATH="data-path"
JSON_FILENAME="public_ids.json"

class IdentityStore(ABC):
    """Abstract class that defines functions for implementations that
    provide IdentityStore functionality - in other words that provide
    storage of the public/private identity key associated with this
    device or requester.
    """
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.SERVICE_NAME = SERVICE_NAME
        self.load()

    def get_private_key(self)->EllipticCurvePrivateKey:
        """Get the private identity key

        Returns:
            EllipticCurvePrivateKey: private identity key
        """
        return self.private_key
    
    def get_public_key(self)->EllipticCurvePublicKey:
        """Get the public identity key

        Returns:
            EllipticCurvePublicKey: public identity key
        """
        return self.public_key

    def get_public_key_id(self)->str:
        """Get the public key id string, which is SHA256 hash of 
        the DER representation of the key

        Returns:
            str: Base64 encoded DER of the public key
        """
        return CryptoUtils.get_public_key_identifier(self.public_key)        

    @abstractmethod
    def get_id(self)->str:
        """Get the ID of this device
        
        This is deprecated and shouldn't be used. We no longer
        set an ID on the PC so there is no reason to store or
        retrieve this value

        Returns:
            str: identity 
        """
        pass
    
    @abstractmethod
    def get_public_identity_from_name(self, name:str)->EllipticCurvePublicKey:
        """Get the public identity key from the device name

        Args:
            name (str): device name

        Returns:
            EllipticCurvePublicKey: device public key
        """
        pass

    @abstractmethod        
    def get_public_identity_from_key_id(self, key_id:str)->EllipticCurvePublicKey:
        """Gets a Public Identity Key from the Key ID, whereby the key_id is 
        a Base64 encoding of the a SHA256 hash of the DER public key bytes

        Args:
            key_id (str): Base64 encoded Public Key ID string

        Returns:
            EllipticCurvePublicKey: Public Key
        """
        pass

    @abstractmethod
    def get_public_key_id_from_name(self, name:str)->str:
        """Gets a public key id from the name provided by the 
        Companion Device during enrolment. Note, names are not
        guaranteed to be unique. It is the responsibility of the
        implementer to determine how to handle duplicates.

        This should return the Public Key ID, if necessary loading
        the key and performing the SHA256 hash and Base64 encoding
        to generate the ID.

        Args:
            name (str): name of the device

        Returns:
            str: Base64 encoding of the Public Key ID
        """
        pass 
    @abstractmethod    
    def get_public_identity_str_from_name(self, name:str)->str:
        """Gets the public key as a Base64 string from the
        device name provided

        Args:
            name (str): device name

        Returns:
            str: Base64 encoded Public Key
        """
        pass
            
    @abstractmethod
    def get_public_identity_str_from_key_id(self, key_id:str)->str:
        """Gets the public key as a Base64 string from the
        key ID provided

        Args:
            key_id (str): Base64 encoding of the SHA256 of the public key bytes

        Returns:
            str: Base64 encoded Public Key
        """
        pass

    @abstractmethod
    def set_public_identity(self, name:str, key:str)->str:
        """Stores a received public identity with the specified name. The
        behaviour for duplicate names is not defined and lef to the
        implementer to decided whether to accept or reject.

        This method should generate the Public Key ID from the key
        string and store that as well.

        Args:
            name (str): name of the device
            key (str): Base64 encoded public key
        """
        pass
    
    @staticmethod
    def calculate_public_key_identifier(key)->str:
        """Utility function to calculate a Public Key ID from a
        key. Calculates the SHA256 hash of the key, encodes it
        with Base64 and returns that string.

        Args:
            key (str or EllipticCurvePublicKey): key to generate Public Key ID from

        Returns:
            str: Base64 encoded SHA256 hash of DER public key bytes
        """
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
        """Deprecated
        Previously used to obtain a PC device name

        Will be removed
        TODO REMOVE

        Returns:
            str: _description_
        """
        q = Queue()
        p = Process(target=UI.get_user_input, args=(q,))
        p.start()
        id=q.get()
        p.join()
        return id
            
    def _generate_identity_key(self):
        """Generates an identity key for the PC and stores them
        """
        print("Generating new keys")
        self.private_key = ec.generate_private_key(ec.SECP256R1)
        self.public_key = self.private_key.public_key()
        self.store()
        
    def get_public_key_encoded_str(self)->str:
        """Gets the public identity key as a Base64 encoded string

        Returns:
            str: Base64 encoded string of DER encoded Public Key bytes
        """
        return CryptoUtils.public_key_to_string(self.public_key)
        

    def get_private_key_encoded_str(self)->str:
        """Gets the private key as encoded string to facilitate storage
        of the key. Currently uses a PEM encoded private key format with
        no encryption.
        
        Returns:
            str: String encoding of the private key
        """
        return self.private_key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8, NoEncryption()).decode("UTF-8")
    
    def load_public_key(self, encoded_public_key:str):
        """Loads the identity public key for this PC from an encoded string

        Args:
            encoded_public_key (str): Base64 encoded Public Key
        """
        self.public_key = CryptoUtils.load_public_key_from_string(encoded_public_key)
    
    def load_private_key(self, pem_encoded_private_key:str):
        """Loads the identity private key for this PC from an encoded string

        Args:
            pem_encoded_private_key (str): PEM encoded private key
        """
        self.private_key = serialization.load_pem_private_key(pem_encoded_private_key.encode("UTF-8"),None)
    @abstractmethod
    def load(self,**kwargs):
        """Loads the underlying store
        """
        pass

    @abstractmethod
    def store(self,**kwargs):
        """Store the data to disk
        """
        pass
    
    @abstractmethod
    def get_key_ids(self):
        """Get the key IDs contained in the store
        """
        pass

    @abstractmethod
    def get_key_names(self):
        """Get the key names contained in the store
        """
        pass

class StorageException(Exception):
    pass
class PublicIdentityStore(ABC):

    @abstractmethod
    def save(self):
        """Save the data to disk
        """
        pass
    
    @abstractmethod
    def load(self):
        """Load the data from disk
        """
        pass
    
    @abstractmethod
    def get_public_identity_str_from_name(self, name:str)->str:
        """Gets the public key as a Base64 string from the
        device name provided

        Args:
            name (str): device name

        Returns:
            str: Base64 encoded Public Key
        """
        pass
        
    @abstractmethod
    def get_public_identity_str_from_key_id(self, key_id:str)->str:
        """Gets the public key as a Base64 string from the
        key ID provided

        Args:
            key_id (str): Base64 encoding of the SHA256 of the public key bytes

        Returns:
            str: Base64 encoded Public Key
        """
        pass

    @abstractmethod
    def get_public_key_id_from_name(self, name:str)->str:
        """Gets a public key id from the name provided by the 
        Companion Device during enrolment. Note, names are not
        guaranteed to be unique. It is the responsibility of the
        implementer to determine how to handle duplicates.

        This should return the Public Key ID, if necessary loading
        the key and performing the SHA256 hash and Base64 encoding
        to generate the ID.

        Args:
            name (str): name of the device

        Returns:
            str: Base64 encoding of the Public Key ID
        """
        pass

    @abstractmethod
    def set_public_identity(self, name:str, key:str)->str:
        """Stores a received public identity with the specified name. The
        behaviour for duplicate names is not defined and lef to the
        implementer to decided whether to accept or reject.

        This method should generate the Public Key ID from the key
        string and store that as well.

        Args:
            name (str): name of the device
            key (str): Base64 encoded public key
        """
        pass
    
    @abstractmethod
    def get_key_ids(self)->List[str]:
        """Get the key IDs contained in the store
        """
        pass

    @abstractmethod
    def get_key_names(self)->List[str]:
        """Get the key names contained in the store
        """
        pass

    @abstractmethod
    def get_id(self)->str:
        """Deprecated
        TODO delete
        Returns:
            str: _description_
        """
        pass
    
    @abstractmethod
    def set_id(self, name:str):
        """Deprecated
        TODO delete

        Args:
            name (str): _description_
        """
        pass


class JSONPublicIdentityStore(PublicIdentityStore):
    """Implementation of the PublicIdentityStore that uses an
    underlying JSON file to read and store values
    """
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
        """Gets the JSON representation directly

        Returns:
            dict: JSON dictionary
        """
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
        """Makes the directories and sets the path variable
        """
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

    #This is only used by the test CD - the PC should never use this
    def get_id(self)->str:
        return self.public_id_store.get_id()

    def _check_initialised(self):
        """Checks whether the key ring and JSONPublicIdentityStore are
        initialised and if not initialises them
        """
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
        
        #This has been removed in favour of setting a device name on the Companion Device
        #TODO Delete below after testing
        #if(self.public_id_store.get_id() is None):
        #    self.public_id_store.set_id(self.get_identity_name())
        #    
        #    if(self.public_id_store.get_id() is None or self.public_id_store.get_id() == ""):
        #        self.public_id_store.set_id(socket.gethostname())
        #    if(self.public_id_store.get_id() is None):
        #        raise Exception("Unable to set device id")
            
            
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
        #keyring.set_password(self.SERVICE_NAME,IDENTITY,self.id)
        keyring.set_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE,self.get_private_key_encoded_str())
        keyring.set_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC,self.get_public_key_encoded_str())
    
    def get_key_ids(self):
        return self.public_id_store.get_key_ids()

    def get_key_names(self):
        return self.public_id_store.get_key_names()
    
    def load(self,**kwargs):
        #self.id = self.id =keyring.get_password(self.SERVICE_NAME,IDENTITY)
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE) is not None):
            self.load_private_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PRIVATE))
            
        if(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC) is not None):
            self.load_public_key(keyring.get_password(self.SERVICE_NAME,IDENTITY_KEY_PUBLIC))

if __name__ == "__main__":
    identity = KeyRingIdentityStore()
