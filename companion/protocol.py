#!/usr/bin/env python
import os
from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey,EllipticCurvePrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from enum import Enum
import base64
from typing import List
import json
import sys
import logging

from companion.identity import IdentityStore, KeyRingIdentityStore
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler(sys.stdout)
logger.addHandler(streamHandler)

class B64():
    @staticmethod
    def encode(data:bytes)->str:
        return base64.encodebytes(data).decode("UTF-8")
    
    @staticmethod
    def decode(b64string:str)->bytes:
        return base64.decodebytes(b64string.encode("UTF-8"))

class ProtocolException(Exception):
    pass

class EncryptedProtocolException(Exception):
    pass

class SignatureException(Exception):
    pass


#*************************************************************************
# Constants
#*************************************************************************
class STATE(Enum):
    pass

class EMPTY_STATE(STATE,Enum):
    EMPTY = 0

class KEP_STATE(STATE,Enum):
    EMPTY = 0
    INIT_KEY_REQ = 1
    INIT_KEY_RESP = 2
    KEY_CONFIRM_REQ = 3
    KEY_CONFIRM_RESP = 4

class FIELDS(Enum):
    pass

class PROTO_INIT_KEY_REQ(FIELDS):
    ADR_PC = "adr_pc"
    PC_PUBLIC_KEY = "pc_public_key"
    ID_PC = "id_pc"
    G_X = "g_to_x"
    SIGNATURE_PC = "signature_pc"

class PROTO_INIT_KEY_RESP(FIELDS):
    G_Y = "g_to_y"
    ENC_MSG = "enc_msg" 

class PROTO_INIT_KEY_RESP_SIG(FIELDS):
    G_Y = "g_to_y"
    G_X = "g_to_x"
    ADR_CD = "adr_cd"
    ID_CD = "id_cd"
    CD_PUBLIC_KEY = "cd_public_key"
    
    
class PROTO_INIT_KEY_RESP_ENC_MSG(FIELDS):
    ADR_CD = "adr_cd"
    ID_CD = "id_cd"
    CD_PUBLIC_KEY = "cd_public_key"
    SIGNATURE_CD = "signature_cd"
    
class PROTO_KEY_CONFIRM(FIELDS):
    ENC_SIG = "enc_sig_confirm"

class PROTO_KEY_CONFIRM_ENC_MSG(FIELDS):
    SIGNATURE_CONFIRM = "signature"
class PROTO_KEY_CONFIRM_SIG(FIELDS):
    G_X = "g_to_x"
    G_Y = "g_to_y"
    

class PROTO_ENC_MSG(FIELDS):
    IV = "iv"
    CIPHER_TEXT = "cipher_text"

class PROTO_EMPTY(FIELDS):
    pass

#*************************************************************************
# Abstract Protocol Message Classes
#*************************************************************************
class ProtocolMessage(ABC):
    
    def __init__(self,data:dict):
        self._data =data
        self.fields = FIELDS
        self.state = EMPTY_STATE.EMPTY

    def get_string(self)->str:
        return json.dumps(self._data)
    
    def get_data(self)->dict:
        return self._data
    @classmethod
    def parse(cls, msg:dict)->'ProtocolMessage':
        temp_obj = cls(msg)
        if temp_obj._validate():
            return temp_obj
        else:
            return None

    def _validate(self)->bool:
        for field in self.fields:
            if(field.value not in self._data):
                print("fieldError:" + field.value)
                return False
        for field in self._data:
            try:
                self.fields(field)
            except ValueError:
                print("valueError:" + field)
                return False
            
        return True

    @abstractstaticmethod
    def create_msg_data(**kwargs):
        pass

class STSDHECKeyExchangeMessage(ABC):
    @abstractmethod
    def get_ephe_public_key(self)->str:
        pass


class SignatureMessage(ProtocolMessage):
    def __init__(self, data:dict):
        super().__init__(data)
        self.signature_fields = self.fields
        self._data = data
    def sign_message(self, signing_key:EllipticCurvePrivateKey, signature_field:FIELDS=None, additional_data:dict = {}):
        logger.debug("sign_message called with override fields: %s", signature_field)
        candidate_signature_store= self._search_for_candidate_signature_field(signature_field)
        assert(candidate_signature_store is not None)
        logger.debug("final signature field: %s", candidate_signature_store)
        chosen_hash = hashes.SHA256()
        digest = self._calculate_digest(chosen_hash,candidate_signature_store,additional_data)
        
        sig = signing_key.sign(digest,ec.ECDSA(utils.Prehashed(chosen_hash)))
        
        self._data[candidate_signature_store.value]=B64.encode(sig)

    def verify_signature(self, verification_key:EllipticCurvePublicKey, signature_field:FIELDS=None, additional_data:dict = {})->bool:
        logger.debug("verify_signature called with override fields: %s", signature_field)
        candidate_signature_store= self._search_for_candidate_signature_field(signature_field)
        assert(candidate_signature_store is not None)
        logger.debug("final signature field: %s", candidate_signature_store)
        chosen_hash = hashes.SHA256()
        digest = self._calculate_digest(chosen_hash,candidate_signature_store,additional_data)
        
        self._data[candidate_signature_store.value]
        try:
            verification_key.verify(B64.decode(self._data[candidate_signature_store.value]),digest,ec.ECDSA(utils.Prehashed(chosen_hash)))
            logger.debug("Signature verified")
            return True
        except InvalidSignature:
            logger.error("Signature verification failed")
            return False

    def _calculate_digest(self, chosen_hash, candidate_signature_store:FIELDS, additional_data:dict = {})->bytes:
        
        hasher = hashes.Hash(chosen_hash)

        for field in self.signature_fields:
            if not field == candidate_signature_store:
                data_obj = None
                if field.value in additional_data:
                    logger.debug("Found %s in additional data", field)
                    data_obj=additional_data[field.value]
                else:
                    logger.debug("Found %s in self._data", field)
                    data_obj=self._data[field.value]
                assert(data_obj is not None)
                logger.debug("Adding %s to signature hash", field)
                if isinstance(data_obj,dict):
                    hasher.update(json.dumps(data_obj).encode("UTF-8"))
                elif isinstance(data_obj,str):
                    hasher.update(data_obj.encode("UTF-8"))
                else:
                    raise SignatureException("Unknown field data type")
            else:
                logger.debug("Excluding %s from signature ", field)
        
        return hasher.finalize()

    def _search_for_candidate_signature_field(self, signature_field:FIELDS)->FIELDS:
        candidate_signature_store = None
        for field in self.fields:
            if signature_field is None and field.name.startswith("SIGNATURE_"):
                if candidate_signature_store is not None:
                    raise SignatureException("Cannot infer signature field from field names")
                else:
                    candidate_signature_store = field
                    logger.debug("Found candidate signature field: %s", candidate_signature_store)

        if candidate_signature_store is None and signature_field is None:
            raise SignatureException("Cannot infer signature field from field names")
        elif candidate_signature_store is None and signature_field is not None:
            candidate_signature_store = signature_field
        return candidate_signature_store

class ProtoEmpty(ProtocolMessage):
    def __init__(self, data:dict):
        super().__init__(data)
        self.fields = PROTO_EMPTY
        self.state = EMPTY_STATE.EMPTY
        self._data = data
    
    @staticmethod
    def create_msg_data():
        data = {}
        return data

class AESGCMEncryptedMessage(ProtocolMessage):
    def __init__(self, data:dict):
        super().__init__(data)
        self.fields = PROTO_ENC_MSG
        #By default this may be embedded in another state so we set STATE to empty
        self.state = EMPTY_STATE.EMPTY
        self._data = data

    @staticmethod
    def create_msg_data(iv:bytes,cipher_text:bytes)->dict:
        data = {}
        data[PROTO_ENC_MSG.IV.value]=B64.encode(iv)
        data[PROTO_ENC_MSG.CIPHER_TEXT.value]=B64.encode(cipher_text)
        return data
    
    def decrypt_json(self, secret_key:bytes)->dict:
        aesgcm = AESGCM(secret_key)
        decrypted_string = aesgcm.decrypt(B64.decode(self._data[PROTO_ENC_MSG.IV.value]),B64.decode(self._data[PROTO_ENC_MSG.CIPHER_TEXT.value]),None).decode('utf-8')
        return json.loads(decrypted_string)
    
    @staticmethod
    def create_encrypted_json_msg_data(data:dict, secret_key:bytes)->dict:
        aesgcm = AESGCM(secret_key)
        nonce = os.urandom(12)
        cipher_text = aesgcm.encrypt(nonce,json.dumps(data).encode('utf-8'),None)
        return AESGCMEncryptedMessage.create_msg_data(nonce,cipher_text)
    
    @staticmethod
    def create_encrypted_json_msg(data:dict, secret_key:bytes)->dict:
        return AESGCMEncryptedMessage.parse(AESGCMEncryptedMessage.create_encrypted_json_msg_data(data,secret_key))
#*************************************************************************
# Abstract Protocol Classes
#*************************************************************************

class Protocol(ABC):
    def __init__(self):
        self.states = EMPTY_STATE
        self.current_state = self.states.EMPTY
        self.protocol_messages=[ProtoEmpty]
  
    def _increment_state(self):
        self.current_state = self.states(self.current_state.value+1)
    def prepare_outgoing_msg(self, data:dict)->ProtocolMessage:
        next_state = self.current_state.value + 1
        if len(self.protocol_messages)<=next_state:
            raise ProtocolException("Exceeded defined states in the protocol")
        
        next_msg = self.protocol_messages[next_state].parse(data)
        if(next_msg is None):
            raise ProtocolException("Missing parameters for next message")
        self._increment_state()
        self.process_outgoing_message(next_msg)
        return next_msg

    def parse_incoming_msg(self, msg:str)->ProtocolMessage:
        data = json.loads(msg)
        if len(self.protocol_messages)>self.current_state.value+1:
            protocol_message = self.protocol_messages[self.current_state.value+1].parse(data)
            if protocol_message is None:
                return None
            self._increment_state()
            self.process_incoming_message(protocol_message)
            return protocol_message
        return None
    
    def process_outgoing_message(self, message:ProtocolMessage):
        pass

    def process_incoming_message(self, message:ProtocolMessage):
        pass

class STSDHKeyExchangeProtocol(Protocol):
    def __init__(self):
        super().__init__()
        self.ephe_private = None
        self.ephe_public = None
        self.server_public = None
        self.shared_key = None
        self.derived_key = None
    
    def generate_secret(self):
        self.ephe_private = ec.generate_private_key(ec.SECP256R1())
        self.ephe_public = self.ephe_private.public_key()

    def get_ephe_public_key_string(self):
        return self.ephe_public.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode("UTF-8")

    def get_server_public_key_string(self):
        return self.server_public.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode("UTF-8")

    def receive_server_public_key(self, server_public_key_pem:str):
        self.server_public = serialization.load_pem_public_key(server_public_key_pem.encode("UTF-8"))
        self.shared_key = self.ephe_private.exchange(ec.ECDH(), self.server_public)
        self.derived_key = HKDF(algorithm=hashes.SHA256(),
                                length=32,
                                salt=None,
                                info=b'STS Handshake data',
                            ).derive(self.shared_key)
        return self.derived_key


class STSDHKEwithAESGCMEncrypedMessageProtocol(STSDHKeyExchangeProtocol):
    def __init__(self):
        super().__init__()

    def decrypt_json_message(self, enc_msg:str)->dict:
        msg = AESGCMEncryptedMessage.parse(enc_msg)
        if msg is None:
            raise EncryptedProtocolException("Error parsing the encrypted message")
        return msg.decrypt_json(self.derived_key)

    def encrypt_json_message(self, msg:dict)->AESGCMEncryptedMessage:
        return AESGCMEncryptedMessage.create_encrypted_json_msg(msg,self.derived_key)




#*************************************************************************
# Concrete Protocol Message Classes
#*************************************************************************

class ProtoMsgInitKeyReq(SignatureMessage,STSDHECKeyExchangeMessage ):
    def __init__(self, data:dict):
        super().__init__(data)
        self.fields = PROTO_INIT_KEY_REQ
        self.signature_fields = self.fields
        self.state = KEP_STATE.INIT_KEY_REQ
        self._data = data

    def get_id(self):
        return self._data[PROTO_INIT_KEY_REQ.ID_PC.value]

    def get_public_identity(self):
        return self._data[PROTO_INIT_KEY_REQ.PC_PUBLIC_KEY.value]
    @staticmethod
    def create_msg_data(adp_pc):
        data = {}
        data[PROTO_INIT_KEY_REQ.ADR_PC.value]=adp_pc
        data[PROTO_INIT_KEY_REQ.ID_PC.value]=""
        data[PROTO_INIT_KEY_REQ.PC_PUBLIC_KEY.value]=""
        data[PROTO_INIT_KEY_REQ.G_X.value]=""
        data[PROTO_INIT_KEY_REQ.SIGNATURE_PC.value]=""
        return data

    def get_ephe_public_key(self)->str:
        return self._data[PROTO_INIT_KEY_REQ.G_X.value]


class ProtoMsgInitKeyRespEncMsg(SignatureMessage):
    def __init__(self, data:dict):
        super().__init__(data)
        self.fields = PROTO_INIT_KEY_RESP_ENC_MSG
        self.signature_fields = PROTO_INIT_KEY_RESP_SIG
        self.state = KEP_STATE.EMPTY
        self._data = data

    def get_id(self):
        return self._data[PROTO_INIT_KEY_RESP_ENC_MSG.ID_CD.value]

    def get_public_identity(self)->str:
        return self._data[PROTO_INIT_KEY_RESP_ENC_MSG.CD_PUBLIC_KEY.value]
        
    @staticmethod
    def create_msg_data(adp_cd):
        data = {}
        data[PROTO_INIT_KEY_RESP_ENC_MSG.ADR_CD.value]=adp_cd
        data[PROTO_INIT_KEY_RESP_ENC_MSG.ID_CD.value]=""
        data[PROTO_INIT_KEY_RESP_ENC_MSG.CD_PUBLIC_KEY.value]=""
        data[PROTO_INIT_KEY_RESP_ENC_MSG.SIGNATURE_CD.value]=""
        return data

class ProtoMsgConfirmKeyMsg(AESGCMEncryptedMessage):
    def __init__(self, data:dict):
        super().__init__(data)
        self.fields = PROTO_KEY_CONFIRM
        self.state = KEP_STATE.KEY_CONFIRM_REQ
        self._data = data

    @staticmethod
    def create_msg_data(enc_msg:AESGCMEncryptedMessage):
        data = {}
        data[PROTO_KEY_CONFIRM.ENC_SIG.value]=enc_msg.get_data()
        return data
    
    def get_encrypted_data(self):
        return self._data[PROTO_KEY_CONFIRM.ENC_SIG.value]

class ProtoMsgConfirmKeyEncMsg(SignatureMessage):
    def __init__(self, data:dict):
        super().__init__(data)
        self.fields = PROTO_KEY_CONFIRM_ENC_MSG
        self.signature_fields = PROTO_KEY_CONFIRM_SIG
        self.state = KEP_STATE.EMPTY
        self._data = data

    @staticmethod
    def create_msg_data():
        data = {}
        data[PROTO_KEY_CONFIRM_ENC_MSG.SIGNATURE_CONFIRM.value]=""
        return data


class ProtoMsgInitKeyResp(AESGCMEncryptedMessage):
    def __init__(self, data:dict):
        super().__init__(data)
        self.fields = PROTO_INIT_KEY_RESP
        self.state = KEP_STATE.INIT_KEY_RESP
        self._data = data

    @staticmethod
    def create_msg_data(enc_msg:AESGCMEncryptedMessage):
        data = {}
        data[PROTO_INIT_KEY_RESP.G_Y.value]=""
        data[PROTO_INIT_KEY_RESP.ENC_MSG.value]=enc_msg.get_data()
        return data
    
    def get_ephe_public_key(self)->str:
        return self._data[PROTO_INIT_KEY_RESP.G_Y.value]
    
    def get_encrypted_data(self):
        return self._data[PROTO_INIT_KEY_RESP.ENC_MSG.value]
    #def get_decrypted_msg(self, derived_key:bytes)->dict:
    #    return ProtoMsgInitKeyResp.decrypt_json(self._data[PROTO_INIT_KEY_RESP.ENC_MSG.value],derived_key)
        


        
#*************************************************************************
# Concrete Protocol Classes
#*************************************************************************

class EnrolmentProtocol(STSDHKEwithAESGCMEncrypedMessageProtocol):
    def __init__(self, identity_store:IdentityStore):
        super().__init__()
        self.states = KEP_STATE
        self.current_state = self.states.EMPTY
        self.protocol_messages.extend([ProtoMsgInitKeyReq,ProtoMsgInitKeyResp,ProtoMsgConfirmKeyMsg])
        self.identity_store = identity_store
        self.pc_id = None
        self.cd_id = None
    
    def process_outgoing_message(self, message:ProtocolMessage):
        if isinstance(message,ProtoMsgInitKeyReq):
            self.generate_secret()
            message._data[PROTO_INIT_KEY_REQ.G_X.value] = self.get_ephe_public_key_string()
            message._data[PROTO_INIT_KEY_REQ.ID_PC.value]=self.identity_store.get_id()
            message._data[PROTO_INIT_KEY_REQ.PC_PUBLIC_KEY.value]=self.identity_store.get_public_key_encoded_str()
            self.pc_id = self.identity_store.get_id()
        if isinstance(message,ProtoMsgInitKeyResp):
            message._data[PROTO_INIT_KEY_RESP.G_Y.value] = self.get_ephe_public_key_string()
        if isinstance(message,ProtoMsgInitKeyRespEncMsg):
            message._data[PROTO_INIT_KEY_RESP_ENC_MSG.CD_PUBLIC_KEY.value] = self.identity_store.get_public_key_encoded_str()
            message._data[PROTO_INIT_KEY_RESP_ENC_MSG.ID_CD.value] = self.identity_store.get_id()
            self.cd_id = self.identity_store.get_id()

        #This should go last to ensure auto data has been added
        if isinstance(message,SignatureMessage):
            if isinstance(message,ProtoMsgInitKeyRespEncMsg):
                message.sign_message(self.identity_store.get_private_key(),None,{PROTO_INIT_KEY_RESP_SIG.G_Y.value:self.get_ephe_public_key_string(),PROTO_INIT_KEY_RESP_SIG.G_X.value:self.get_server_public_key_string()})
            elif isinstance(message,ProtoMsgConfirmKeyEncMsg):
                message.sign_message(self.identity_store.get_private_key(),None,{PROTO_INIT_KEY_RESP_SIG.G_Y.value:self.get_server_public_key_string(),PROTO_INIT_KEY_RESP_SIG.G_X.value:self.get_ephe_public_key_string()})
            
            else:
                message.sign_message(self.identity_store.get_private_key())
            
    def process_incoming_message(self, message:ProtocolMessage):
        if isinstance(message,ProtoMsgInitKeyReq):
            self.generate_secret()
            self.receive_server_public_key(message.get_ephe_public_key())
            self.pc_id = message.get_id()
            self.identity_store.set_public_identity(message.get_id(),message.get_public_identity())
        if isinstance(message,ProtoMsgInitKeyResp):
            self.receive_server_public_key(message.get_ephe_public_key())
            init_key_resp = ProtoMsgInitKeyRespEncMsg.parse(self.decrypt_json_message(message.get_encrypted_data()))
            self.identity_store.set_public_identity(init_key_resp.get_id(),init_key_resp.get_public_identity())
            temp_key =  serialization.load_pem_public_key(init_key_resp.get_public_identity().encode("UTF-8"))
            self.cd_id = init_key_resp.get_id()
            if not init_key_resp.verify_signature(temp_key,None,{PROTO_INIT_KEY_RESP_SIG.G_X.value:self.get_ephe_public_key_string(),PROTO_INIT_KEY_RESP_SIG.G_Y.value:self.get_server_public_key_string()}):
                raise ProtocolException("Signature verification failed")
        if isinstance(message,SignatureMessage):
            if isinstance(message,ProtoMsgConfirmKeyEncMsg):
                if not message.verify_signature(self.identity_store.get_public_identity(self.cd_id),None,{PROTO_INIT_KEY_RESP_SIG.G_X.value:self.get_server_public_key_string(),PROTO_INIT_KEY_RESP_SIG.G_Y.value:self.get_ephe_public_key_string()}):
                    raise ProtocolException("Signature verification failed")
            else:
                message.verify_signature(self.identity_store.get_public_identity(message.get_id()))
            



