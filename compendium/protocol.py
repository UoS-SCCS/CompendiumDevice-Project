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

import json
import logging
import os
import sys
from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod
from enum import Enum
from operator import add
from typing import List, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          PublicFormat)

from compendium.storage import IdentityStore, KeyRingIdentityStore
from compendium.utils import B64, CryptoUtils

#General logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler(sys.stdout)
logger.addHandler(streamHandler)

#Protocol specific logger
protologger = logging.getLogger("protocol-messages")
protologger.setLevel(logging.DEBUG)
protologger.addHandler(streamHandler)


class ProtocolException(Exception):
    """General protocol exception"""
    pass

class EncryptedProtocolException(Exception):
    """Exception for encrypted protocols, normally
    used to signify and decryption failure"""
    pass

class SignatureException(Exception):
    """Exception for signature checking
    """
    pass

class ProtocolRemoteException(Exception):
    """Remote exception used to wrap an incoming error
    message so it can be propogated through an exception
    call

    """
    def __init__(self, err_code:int, err_msg:str, *args: object) -> None:
        """Create a new Remote Exception with error code and message

        Args:
            err_code (int): error code received
            err_msg (str): error message received
        """
        super().__init__(*args)
        self.err_code=err_code
        self.err_msg = err_msg

#*************************************************************************
# Constants
#*************************************************************************
class STATE(Enum):
    pass

class EMPTY_STATE(STATE,Enum):
    EMPTY = 0

class FIELDS(Enum):
    pass

#*************************************************************************
# Enrol Protocol
#*************************************************************************
class ENROL_KEP_STATE(STATE,Enum):
    """States for the enrolment protocol
    """
    EMPTY = 0
    INIT_KEY_REQ = 1
    INIT_KEY_RESP = 2
    KEY_CONFIRM_REQ = 3

class PROTO_ENROL_INIT_KEY_REQ(FIELDS):
    """Fields for the INIT KEY REQUEST
    """
    ADR_PC = "adr_pc"
    PC_PUBLIC_KEY = "pc_public_key"
    G_X = "g_to_x"
    SIGNATURE_PC = "signature_pc"

class PROTO_ENROL_INIT_KEY_RESP_SIG(FIELDS):
    G_Y = "g_to_y"
    G_X = "g_to_x"
    ADR_CD = "adr_cd"
    ID_CD = "id_cd"
    CD_PUBLIC_KEY = "cd_public_key"
    
class PROTO_ENROL_INIT_KEY_RESP_ENC_MSG(FIELDS):
    ADR_CD = "adr_cd"
    ID_CD = "id_cd"
    CD_PUBLIC_KEY = "cd_public_key"
    SIGNATURE_CD = "signature_cd"

#*************************************************************************
# WSS Protocol
#*************************************************************************
class WSS_KEP_STATE(STATE,Enum):
    EMPTY = 0
    INIT_KEY_REQ = 1
    INIT_KEY_RESP = 2
    KEY_CONFIRM_REQ = 3
    CORE_REQ = 4
    CORE_RESP = 5

class PROTO_WSS_INIT_KEY_REQ(FIELDS):
    ADR_PC = "adr_pc"
    HASH_PC_PUBLIC_KEY = "hash_pc_public_key"
    G_X = "g_to_x"
    SIGNATURE_PC = "signature_pc"

class PROTO_WSS_INIT_KEY_REQ_SIG(FIELDS):
    ID_CD = "id_cd"
    ADR_PC = "adr_pc"
    G_X = "g_to_x"

class PROTO_WSS_INIT_KEY_RESP_SIG(FIELDS):
    G_Y = "g_to_y"
    G_X = "g_to_x"
    ADR_CD = "adr_cd"
    
class PROTO_WSS_INIT_KEY_RESP_ENC_MSG(FIELDS):
    ADR_CD = "adr_cd"
    HASH_CD_PUBLIC_KEY = "hash_cd_public_key"
    SIGNATURE_CD = "signature_cd"

#*************************************************************************
# Common Key Confirm
#*************************************************************************

class PROTO_INIT_KEY_RESP(FIELDS):
    G_Y = "g_to_y"
    ENC_MSG = "enc_msg" 


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
# Core Message Fields
#*************************************************************************
class PROTO_CORE(FIELDS):
    ENC_MSG = "enc_msg"

class PROTO_CORE_REG_REQ(FIELDS):
    TYPE = "type"
    ID_CD = "id_cd"
    APP_ID ="app_id"
    DESC = "desc"
    SIGNATURE_MSG = "signature"

class PROTO_CORE_REG_RES(FIELDS):
    TYPE = "type"
    APP_ID ="app_id"
    APP_PK ="app_pk"
    SIGNATURE_MSG = "signature"

class PROTO_CORE_VERIFY_REQ(FIELDS):
    TYPE = "type"
    ID_CD = "id_cd"
    APP_ID ="app_id"
    DESC = "desc"
    CODE = "code"
    NONCE = "nonce"
    SIGNATURE_MSG = "signature"

class PROTO_CORE_VERIFY_RES(FIELDS):
    TYPE = "type"
    APP_ID ="app_id"
    APP_SIG ="app_sig"
    SIGNATURE_MSG = "signature"

class PROTO_CORE_PUT_REQ(FIELDS):
    TYPE = "type"
    ID_CD = "id_cd"
    APP_ID ="app_id"
    DESC = "desc"
    CODE = "code"
    DATA = "data"
    SIGNATURE_MSG = "signature"

class PROTO_CORE_PUT_RES(FIELDS):
    TYPE = "type"
    ENC_DATA ="encdata"
    SIGNATURE_MSG = "signature"


class PROTO_CORE_GET_REQ(FIELDS):
    TYPE = "type"
    ID_CD = "id_cd"
    APP_ID ="app_id"
    DESC = "desc"
    CODE = "code"
    ENC_DATA = "encdata"
    SIGNATURE_MSG = "signature"

class PROTO_CORE_GET_RES(FIELDS):
    TYPE = "type"
    DATA ="data"
    SIGNATURE_MSG = "signature"

class PROTO_CORE_RESP_ERR(FIELDS):
    ERROR_CONDITION = "err"
    SIGNATURE_MSG = "signature"

class ERROR_MESSAGE(FIELDS):
    TYPE = "type"
    ERROR_CONDITION = "error-condition"
    SIGNATURE_MSG = "signature"
#*************************************************************************
# Abstract Protocol Message Classes
#*************************************************************************
class ProtocolMessage(ABC):
    """Generic abstract protocol message that all other protocol messages
    must subclass. Provides essential functionality like parsing and 
    message verification by checking the relevant field enums for the
    presence of the appropriate fields
    """
    def __init__(self,data:dict):
        """Create a new protocol message with the specified data

        Args:
            data (dict): initial data
        """
        self._data =data
        self.fields = FIELDS
        self.state = EMPTY_STATE.EMPTY

    def get_string(self)->str:
        """Gets a JSON string representation of the data

        Returns:
            str: JSON String of data
        """
        return json.dumps(self._data)
    
    def get_data(self)->dict:
        """Gets the underlying dictionary containing the protocol
        message data

        Returns:
            dict: message data
        """
        return self._data
    @classmethod
    def parse(cls, msg:dict)->'ProtocolMessage':
        """Parse the specified dictionary using the 
        specified class and validate. This will use
        whatever the underlying subclass is in order to parse the 
        message.

        Args:
            msg (dict): data to parse

        Returns:
            ProtocolMessage: appropriate subclass protocol message 
                    if it passes the validation, otherwise None 
        """
        temp_obj = cls(msg)
        if temp_obj._validate():
            return temp_obj
        else:
            return None

    def _validate(self)->bool:
        """Validate the message against the expected fields, this
        checks both that all fields appear in the message and that
        not fields are than expected fields appear

        Returns:
            bool: True if valid, False if not
        """
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
        """Generic abstract method to be overridden as a helper
        function to generate a valid message. It is expected that
        subclasses will explicitly list the require fields in the
        method signature
        """
        pass

class STSDHECKeyExchangeMessage(ABC):
    """Abstract class that represents the STS Diffie-Hellman key exchange
    requires one method to be implemented, that to get the ephemeral public
    key generated as part of the STS-DH

    """
    @abstractmethod
    def get_ephe_public_key(self)->str:
        pass


class SignatureMessage(ProtocolMessage):
    """Defines an interface for messages that contain a signature and
    provides the functionality to both sign and verify those messages.

    This should be included as one of the super classes for any message
    wishing to sign or verify a signature
    """
    def __init__(self, data:dict):
        """Constructor to create a new signature message from some data

        Args:
            data (dict): initial data
        """
        super().__init__(data)
        self.signature_fields = self.fields
        self._data = data
    def sign_message(self, signing_key:EllipticCurvePrivateKey, signature_field:FIELDS=None, additional_data:dict = {}):
        """Signs a message using the specified private key, targeting a specific
        signature_field for output.

        It will attempt to find an appropriate signature destination field and then exclude that from the hash

        Args:
            signing_key (EllipticCurvePrivateKey): private key to sign with
            signature_field (FIELDS, optional): Overrides the automatic detection of the output signature field. Defaults to None.
            additional_data (dict, optional): Additional data that might be included in the signature but not the message. Defaults to {}.
        """
        logger.debug("sign_message called with override fields: %s", signature_field)
        candidate_signature_store= self._search_for_candidate_signature_field(signature_field)
        assert(candidate_signature_store is not None)
        logger.debug("final signature field: %s", candidate_signature_store)
        chosen_hash = hashes.SHA256()
        digest = self._calculate_digest(chosen_hash,candidate_signature_store,additional_data)
        
        sig = signing_key.sign(digest,ec.ECDSA(utils.Prehashed(chosen_hash)))
        
        self._data[candidate_signature_store.value]=B64.encode(sig)

    def verify_signature(self, verification_key:EllipticCurvePublicKey, signature_field:FIELDS=None, additional_data:dict = {})->bool:
        """Verifies a signature using the specified verification key

        It will attempt to find a suitable signature field to obtain the signature from and exclude
        that field from the hash. This can be overridden using signature_field

        Args:
            verification_key (EllipticCurvePublicKey): Public key to use for verification
            signature_field (FIELDS, optional): override automatic signature field detection. Defaults to None.
            additional_data (dict, optional): additional data that might be in the signature but not the message. Defaults to {}.

        Returns:
            bool: _description_
        """
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
        """Calculates the digest of this message, excluding the signature field and using additional_data
        for values that do not appear in the message itself

        Args:
            chosen_hash (str): hash name
            candidate_signature_store (FIELDS): field to use for signature and therefore exclude from the hash
            additional_data (dict, optional): additional data to add to the hash if not in the message. Defaults to {}.

        Raises:
            SignatureException: if the hash generation fails

        Returns:
            bytes: hash digest of the data
        """
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
                logger.debug("Adding %s to signature hash: %s", field, data_obj)
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
        """Looks for a candidate field to store the signature in, it does this
        by looking for the prefix SIGNATURE_ in the field name

        If no such field exists fallsback to signature_field

        Args:
            signature_field (FIELDS): field to use if no automatic field can be detected

        Raises:
            SignatureException: if not signature field can be found

        Returns:
            FIELDS: field to use for signature storage
        """
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
    """Empty protocol message
    """
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
    """Represents an AESGCM encrypted message of the type used
    following the STS-DH. This handles the encryption and decryption
    of message content.
    """
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
        """Decrypt the JSON object containing an IV and cipher text
        using the supplied secret key.

        Args:
            secret_key (bytes): decryption key,  usually the derived session key

        Returns:
            dict: decrypted JSON object
        """
        aesgcm = AESGCM(secret_key)
        decrypted_string = aesgcm.decrypt(B64.decode(self._data[PROTO_ENC_MSG.IV.value]),B64.decode(self._data[PROTO_ENC_MSG.CIPHER_TEXT.value]),None).decode('utf-8')
        return json.loads(decrypted_string)
    
    @staticmethod
    def create_encrypted_json_msg_data(data:dict, secret_key:bytes)->dict:
        """Create an encrypted JSON object from the supplied JSON dictionary
        using the secret_key provided. This will encrypt the contents
        and create a new JSON object containing the IV and the cipher text. That
        data is passed to AESGCMEncryptedMessage to construct a suitable 
        dictionary for that message.

        Args:
            data (dict): JSON to encrypt
            secret_key (bytes): secret key to use

        Returns:
            dict: dictionary containing the fields necessary for AESGCMEncryptedMessage
        """
        aesgcm = AESGCM(secret_key)
        nonce = os.urandom(12)
        cipher_text = aesgcm.encrypt(nonce,json.dumps(data).encode('utf-8'),None)
        return AESGCMEncryptedMessage.create_msg_data(nonce,cipher_text)
    
    @staticmethod
    def create_encrypted_json_msg(data:dict, secret_key:bytes)->ProtocolMessage:
        """Create an AESGCMEncryptedMessage object having first encrypted
        the data provided using the secret key. That data will then be used
        to construct a AESGCMEncryptedMessage object

        Args:
            data (dict): data to be encrypted
            secret_key (bytes): secret key to use

        Returns:
            ProtocolMessage: AESGCMEncryptedMessage message
        """
        protologger.debug("Encrypting: %s",data)
        return AESGCMEncryptedMessage.parse(AESGCMEncryptedMessage.create_encrypted_json_msg_data(data,secret_key))
#*************************************************************************
# Abstract Protocol Classes
#*************************************************************************

class Protocol(ABC):
    """Top level abstract protocol class on which all protocol classes should
    be based. This provides the base functionality shared by all protocols
    but that functionality can be overridden if a protocol requires addition
    processing. In such cases the subclass should almost always call the super
    class method first and then handle its additional processing after.

    """
    def __init__(self):
        """Initialise a new protocol this should contain a reference to an 
        Enum defining the possible states of the protocol and a protocol_messages
        array containing ProtocolMessage classes in the order they are to be
        used and in sync with the states. The state ordinal will be used
        to retrieve an appropriate message type and parse incoming or 
        outgoing messages. It is therefore vital that this is correctly
        synced.
        """
        self.states = EMPTY_STATE
        self.current_state = self.states.EMPTY
        self.protocol_messages=[ProtoEmpty]
  
    def get_next_message_class(self):
        """Get the Message class for the current protocol state by
        retrieving the ordinal of the current_state and returning
        the appropriate class from protocol_messages.

        Returns:
            class: ProtocolMessage - appropriate subclass
        """
        return self.protocol_messages[self.current_state.value+1]

    def _increment_state(self):
        """Increment the state by increasing its ordinal
        """
        self.current_state = self.states(self.current_state.value+1)
    def prepare_outgoing_msg(self, data:dict)->ProtocolMessage:
        """Prepare an outgoing message with the provided data.

        This will retrieve the ProtocolMessage class for the next
        state, parse the provided data into it, and if successfully
        parsed, increment the state of the protocol and call
        prepare_outgoing_message to process the newly
        constructed message object, i.e. encrypt/sign/etc.

        Args:
            data (dict): data to be included in the new message

        Raises:
            ProtocolException: Exception thrown if there are no more states or 
                there are fields missing in the provided data

        Returns:
            ProtocolMessage: ProtocolMessage of the appropriate type ready
            for sending
        """
        next_state = self.current_state.value + 1
        if len(self.protocol_messages)<=next_state:
            raise ProtocolException("Exceeded defined states in the protocol")
        
        next_msg = self.protocol_messages[next_state].parse(data)
        if(next_msg is None):
            raise ProtocolException("Missing parameters for next message")
        self._increment_state()
        self.process_outgoing_message(next_msg)
        protologger.debug("Outgoing: %s",next_msg.get_string())
        return next_msg

    def parse_incoming_msg(self, msg)->ProtocolMessage:
        """Parse an incoming message by retrieving the ProtocolMessage
        subclass associated with the next state and attempting to 
        parse the provided data. If it not successful it will effectively
        reject the message by returning None, otherwise the protocol
        state will be incremented and process_incoming_message will
        be called to process the received message (decrypt/verify/etc)

        Args:
            msg (dict or str): message

        Returns:
            ProtocolMessage: Appropriate ProtocolMessage subclass or None
        """
        if isinstance(msg,dict):
            data = msg
        else:
            data = json.loads(msg)

        
        if len(self.protocol_messages)>self.current_state.value+1:
            protocol_message = self.protocol_messages[self.current_state.value+1].parse(data)
            if protocol_message is None:
                return None
            self._increment_state()
            self.process_incoming_message(protocol_message)
            protologger.debug("Incoming: %s",protocol_message.get_string())
            return protocol_message
        return None
    



    def process_outgoing_message(self, message:ProtocolMessage):
        """Should be overridden by subclassing protocol to perform 
        message specific processing of an outgoing message.

        This is where you should perform any signing, encryption, etc.

        Args:
            message (ProtocolMessage): ProtocolMessage to be processed
        """
        pass

    def process_incoming_message(self, message:ProtocolMessage):
        """Should be overridden by subclassing protocol to perform
        message specific processing of an incoming message.

        This is where you should perform verification, decryption, etc.

        Args:
            message (ProtocolMessage): ProtocolMessage to be processed
        """
        pass

class STSDHKeyExchangeProtocol(Protocol):
    """Protocol that represents the STS Diffie-Hellman key exchange
    protocol. This is not intended to be instantiated directly, but
    rather subclasses by the final target protocol.

    """
    def __init__(self):
        """Initialise with additional parameters for the necessary key
        objects"""
        super().__init__()
        self.ephe_private = None
        self.ephe_public = None
        self.server_public = None
        self.shared_key = None
        self.derived_key = None
    
    def generate_secret(self):
        """Generates an ephemeral key pair for ECDH
        """
        self.ephe_private = ec.generate_private_key(ec.SECP256R1())
        self.ephe_public = self.ephe_private.public_key()

    def get_my_ephe_public_key_string(self):
        """Gets the ephemeral public key as a Base64 encoded string

        Returns:
            str: Base64 encoded ephemeral public key
        """
        return CryptoUtils.public_key_to_string(self.ephe_public)

    def get_their_ephe_public_key_string(self):
        """Gets the ephemeral public key of the other side of the connection
        as a Base64 encoded public key string

        Returns:
            str: Base64 encoded public key from the other side of the connection
        """
        return CryptoUtils.public_key_to_string(self.server_public)
        

    def receive_their_public_key(self, server_public_key:str):
        """Called when receiving their public key, this performs the key 
        derivation function to generate the shared derived key

        Args:
            server_public_key (str): public key from the other party as Base64 encoded string

        Returns:
            bytes: derived 32 byte secret key
        """
        self.server_public = CryptoUtils.load_public_key_from_string(server_public_key)
        self.shared_key = self.ephe_private.exchange(ec.ECDH(), self.server_public)
        self.derived_key = HKDF(algorithm=hashes.SHA256(),
                                length=32,
                                salt=None,
                                info=b'STS Handshake data',
                            ).derive(self.shared_key)
        return self.derived_key


class STSDHKEwithAESGCMEncrypedMessageProtocol(STSDHKeyExchangeProtocol):
    """Expands the STS-DH protocol to layer encrypted JSON message on 
    top. This is the core messaging protocol underlying the higher level
    messaging protocols.

    This class provides the functionality to encrypt and decrypt JSON 
    messages

    """
    def __init__(self):
        super().__init__()

    def decrypt_json_message(self, enc_msg:str)->dict:
        """Decrypt the provided string JSON message, which should consist of an
        IV and Cipher text field. 

        Args:
            enc_msg (str): message string to be parsed and decrypted

        Raises:
            EncryptedProtocolException: thrown if there is an error parsing the message

        Returns:
            dict: decrypted JSON dictionary
        """
        msg = AESGCMEncryptedMessage.parse(enc_msg)
        if msg is None:
            raise EncryptedProtocolException("Error parsing the encrypted message")
        return msg.decrypt_json(self.derived_key)

    def encrypt_json_message(self, msg:dict)->AESGCMEncryptedMessage:
        """Encrypt a JSON message and return an AESGCMEncryptedMessage      

        Args:
            msg (dict): data to encrypt

        Returns:
            AESGCMEncryptedMessage: constructed AESGCMEncryptedMessage message
                containing the encrypted data
        """
        return AESGCMEncryptedMessage.create_encrypted_json_msg(msg,self.derived_key)




#*************************************************************************
# Concrete Protocol Message Classes
#*************************************************************************

#*************************************************************************
# Enrolment Protocol Message Classes
#*************************************************************************

class ProtoMsgInitKeyReq(SignatureMessage,STSDHECKeyExchangeMessage ):
    """Init Key Request message for the enrolment key exchange protocol

    """
    def __init__(self, data:dict):
        """Creates a new Init message for the enrolment protocol

        Args:
            data (dict): data to initialise the message with
        """
        super().__init__(data)
        self.fields = PROTO_ENROL_INIT_KEY_REQ
        self.signature_fields = self.fields
        self.state = ENROL_KEP_STATE.INIT_KEY_REQ
        self._data = data

    def get_sender_public_key_id(self)->str:
        """Calculate the senders public key ID (Base64 encoded SHA256) 

        Returns:
            str: Base64 encoded SHA256 hash of public key bytes
        """
        return IdentityStore.calculate_public_key_identifier(self.get_public_identity())

    def get_ephe_remote_addr(self)->str:
        """Gets the ephemeral address of the remote connection
        which will be the PC

        Returns:
            str: string address for Web Socket Server
        """
        return self._data[PROTO_ENROL_INIT_KEY_REQ.ADR_PC.value]

    def get_public_identity(self)->str:
        """Gets the sender public key from the message data in
        this case the PC public key

        Returns:
            str: Base64 encoded public key
        """
        return self._data[PROTO_ENROL_INIT_KEY_REQ.PC_PUBLIC_KEY.value]
    @staticmethod
    def create_msg_data(adp_pc):
        data = {}
        data[PROTO_ENROL_INIT_KEY_REQ.ADR_PC.value]=adp_pc
        data[PROTO_ENROL_INIT_KEY_REQ.PC_PUBLIC_KEY.value]=""
        data[PROTO_ENROL_INIT_KEY_REQ.G_X.value]=""
        data[PROTO_ENROL_INIT_KEY_REQ.SIGNATURE_PC.value]=""
        return data

    def get_ephe_public_key(self)->str:
        """Gets the g^x value from the message

        Returns:
            str: Base64 encoded g^x
        """
        return self._data[PROTO_ENROL_INIT_KEY_REQ.G_X.value]


class ProtoMsgInitKeyRespEncMsg(SignatureMessage):
    """Response to the Init Key Request
    """
    def __init__(self, data:dict):
        """ Initialise a new Init Key Response message"""
        super().__init__(data)
        self.fields = PROTO_ENROL_INIT_KEY_RESP_ENC_MSG
        self.signature_fields = PROTO_ENROL_INIT_KEY_RESP_SIG
        self.state = ENROL_KEP_STATE.EMPTY
        self._data = data

    def get_ephe_remote_addr(self)->str:
        """Gets the ephemeral remote Web Socket Address - this will
        normally be the Companion Device address

        Returns:
            str: String address
        """
        return self._data[PROTO_ENROL_INIT_KEY_RESP_ENC_MSG.ADR_CD.value]
    def get_name(self):
        """Get the provided name of the Companion Device

        Returns:
            str: Name of the Companion Device
        """
        return self._data[PROTO_ENROL_INIT_KEY_RESP_ENC_MSG.ID_CD.value]
    
    def get_sender_public_key_id(self):
        """Calculate the senders public key ID (Base64 encoded SHA256) 

        Returns:
            str: Base64 encoded SHA256 hash of public key bytes
        """
        return IdentityStore.calculate_public_key_identifier(self.get_public_identity())


    def get_public_identity(self)->str:
        """Gets the sender public key from the message data in
        this case the CD public key

        Returns:
            str: Base64 encoded public key
        """
        return self._data[PROTO_ENROL_INIT_KEY_RESP_ENC_MSG.CD_PUBLIC_KEY.value]
        
    @staticmethod
    def create_msg_data(adr_cd):
        data = {}
        data[PROTO_ENROL_INIT_KEY_RESP_ENC_MSG.ADR_CD.value]=adr_cd
        data[PROTO_ENROL_INIT_KEY_RESP_ENC_MSG.ID_CD.value]=""
        data[PROTO_ENROL_INIT_KEY_RESP_ENC_MSG.CD_PUBLIC_KEY.value]=""
        data[PROTO_ENROL_INIT_KEY_RESP_ENC_MSG.SIGNATURE_CD.value]=""
        return data






#*************************************************************************
# WSS Protocol Message Classes
#*************************************************************************

class ProtoWSSInitKeyReqMsg(SignatureMessage,STSDHECKeyExchangeMessage ):
    """WebSocket Init Key Request to establish a shared key over
    the WSS connection

    """
    def __init__(self, data:dict):
        """Initialise a new WSS Init Key Request

        Args:
            data (dict): _description_
        """
        super().__init__(data)
        self.fields = PROTO_WSS_INIT_KEY_REQ
        self.signature_fields = self.fields
        self.state = WSS_KEP_STATE.INIT_KEY_REQ
        self._data = data

    @staticmethod
    def create_msg_data(adp_pc):
        data = {}
        data[PROTO_WSS_INIT_KEY_REQ.ADR_PC.value]=adp_pc
        data[PROTO_WSS_INIT_KEY_REQ.HASH_PC_PUBLIC_KEY.value]=""
        data[PROTO_WSS_INIT_KEY_REQ.G_X.value]=""
        data[PROTO_WSS_INIT_KEY_REQ.SIGNATURE_PC.value]=""
        return data

    def get_ephe_remote_addr(self)->str:
        """Gets the ephemeral address of the remote connection
        which will be the PC

        Returns:
            str: string address for Web Socket Server
        """
        return self._data[PROTO_WSS_INIT_KEY_REQ.ADR_PC.value]
    
    def get_sender_public_key_id(self)->str:
        """Gets the senders public key ID (Base64 encoded SHA256) 
        from the message

        Returns:
            str: Base64 encoded SHA256 hash of public key bytes
        """
        return self._data[PROTO_WSS_INIT_KEY_REQ.HASH_PC_PUBLIC_KEY.value]

    def get_ephe_public_key(self)->str:
        """Gets the g^x value from the message

        Returns:
            str: Base64 encoded g^x
        """
        return self._data[PROTO_WSS_INIT_KEY_REQ.G_X.value]


class ProtoWSSInitKeyRespEncMsg(SignatureMessage):
    """WebSocket Init Key Response encrypted message, this
    contains the actual message data after decryption and
    is effectively used as an inner message of ProtoMsgInitKeyResp
    """
    def __init__(self, data:dict):
        """Initialise a new Init Key Response message

        Args:
            data (dict): data to initialise it with
        """
        super().__init__(data)
        self.fields = PROTO_WSS_INIT_KEY_RESP_ENC_MSG
        self.signature_fields = PROTO_WSS_INIT_KEY_RESP_SIG
        self.state = ENROL_KEP_STATE.EMPTY
        self._data = data

    def get_sender_public_key_id(self)->str:
        """Get the senders public key ID (Base64 encoded SHA256) 
        from the message

        Returns:
            str: Base64 encoded SHA256 hash of public key bytes
        """
        return self._data[PROTO_WSS_INIT_KEY_RESP_ENC_MSG.HASH_CD_PUBLIC_KEY.value]
    
    def get_ephe_remote_addr(self)->str:
        """Gets the ephemeral address of the remote connection
        which will be the CD

        Returns:
            str: string address for Web Socket Server
        """
        return self._data[PROTO_WSS_INIT_KEY_RESP_ENC_MSG.ADR_CD.value]

    @staticmethod
    def create_msg_data(adr_cd):
        data = {}
        data[PROTO_WSS_INIT_KEY_RESP_ENC_MSG.ADR_CD.value]=adr_cd
        data[PROTO_WSS_INIT_KEY_RESP_ENC_MSG.HASH_CD_PUBLIC_KEY.value]=""
        data[PROTO_WSS_INIT_KEY_RESP_ENC_MSG.SIGNATURE_CD.value]=""
        return data

#*************************************************************************
# Common Message Classes
#*************************************************************************

class ProtoMsgInitKeyResp(AESGCMEncryptedMessage):
    """Generic Init Key Response message that wraps an inner
    encrypted message that contains the actual protocol
    message data. This is the response to the init key request
    and therefore contains a plaintext g^y that will be used
    to derive the shared key

    """
    def __init__(self, data:dict):
        """Initialise the message with the provided data

        Args:
            data (dict): data to initialise with
        """
        super().__init__(data)
        self.fields = PROTO_INIT_KEY_RESP
        #TODO we don't actually use message STATE, so this should be removed 
        #as it isn't consistent with the general use of this message which
        #goes beyond just the enrol protocol
        self.state = ENROL_KEP_STATE.INIT_KEY_RESP
        self._data = data

    @staticmethod
    def create_msg_data(enc_msg:AESGCMEncryptedMessage):
        data = {}
        data[PROTO_INIT_KEY_RESP.G_Y.value]=""
        data[PROTO_INIT_KEY_RESP.ENC_MSG.value]=enc_msg.get_data()
        return data
    
    def get_ephe_public_key(self)->str:
        """Gets the g^y that has been included in the message as a 
        response to the request. This will be used to derive the
        shared key and is thus outside the encrypted block

        Returns:
            str: Base64 encoded g^y
        """
        return self._data[PROTO_INIT_KEY_RESP.G_Y.value]
    
    def get_encrypted_data(self):
        """Gets the encrypted message block

        Returns:
            str: JSON string containing IV and cipher text
        """
        return self._data[PROTO_INIT_KEY_RESP.ENC_MSG.value]

class ProtoMsgConfirmKeyMsg(AESGCMEncryptedMessage):
    """Wrapper for the Key Confirmation message, will
    include a ProtoMsgConfirmKeyEncMsg that contains the
    actual protocol message data

    """
    def __init__(self, data:dict):
        """Initialise a new Key Confirm message

        Args:
            data (dict): data to initialise with
        """
        super().__init__(data)
        self.fields = PROTO_KEY_CONFIRM
        self.state = ENROL_KEP_STATE.KEY_CONFIRM_REQ
        self._data = data

    @staticmethod
    def create_msg_data(enc_msg:AESGCMEncryptedMessage):
        data = {}
        data[PROTO_KEY_CONFIRM.ENC_SIG.value]=enc_msg.get_data()
        return data
    
    def get_encrypted_data(self):
        """Gets the encrypted data in this case an encrypted
        signature

        Returns:
            str: JSON str containing IV and cipher text
        """
        return self._data[PROTO_KEY_CONFIRM.ENC_SIG.value]

class ProtoMsgConfirmKeyEncMsg(SignatureMessage):
    """Inner encrypted message contained within ProtoMsgConfirmKeyMsg
    """
    def __init__(self, data:dict):
        """initialise a new Confirm Key Encrypted Message

        Args:
            data (dict): data to initialise with
        """
        super().__init__(data)
        self.fields = PROTO_KEY_CONFIRM_ENC_MSG
        self.signature_fields = PROTO_KEY_CONFIRM_SIG
        self.state = ENROL_KEP_STATE.EMPTY
        self._data = data

    @staticmethod
    def create_msg_data():
        data = {}
        data[PROTO_KEY_CONFIRM_ENC_MSG.SIGNATURE_CONFIRM.value]=""
        return data        

#*************************************************************************
# Core Message Classes
#*************************************************************************
class ProtoMsgCoreMsg(AESGCMEncryptedMessage):
    """Core message to be used by the higher level get, put, reg
    and verify message. This will contain an inner encrypted message

    """
    def __init__(self, data:dict):
        """Initialise a new Core request message

        Args:
            data (dict): data to initialise with
        """
        super().__init__(data)
        self.fields = PROTO_CORE# sub_message
        self.state = WSS_KEP_STATE.CORE_REQ
        self._data = data

    @staticmethod
    def create_msg_data(enc_msg:AESGCMEncryptedMessage):
        data = {}
        data[PROTO_CORE.ENC_MSG.value]=enc_msg.get_data()
        return data
    
    def get_encrypted_data(self):
        """Gets the encrypted blob

        Returns:
            str: JSON string containing IV and cipher text
        """
        return self._data[PROTO_CORE.ENC_MSG.value]

class ProtoMsgCoreRespMsg(AESGCMEncryptedMessage):
    """Core response message to be used by the higher level get, put, reg
    and verify message. This will contain an inner encrypted message

    """
    def __init__(self, data:dict):
        """Initialise a new Core response message

        Args:
            data (dict): data to initialise with
        """
        super().__init__(data)
        self.fields = PROTO_CORE# sub_message
        self.state = WSS_KEP_STATE.CORE_RESP
        self._data = data

    @staticmethod
    def create_msg_data(enc_msg:AESGCMEncryptedMessage):
        data = {}
        data[PROTO_CORE.ENC_MSG.value]=enc_msg.get_data()
        return data
    
    def get_encrypted_data(self):
        """Gets the encrypted blob

        Returns:
            str: JSON string containing IV and cipher text
        """
        return self._data[PROTO_CORE.ENC_MSG.value]

class ProtoMsgCoreEncMsg(SignatureMessage):
    """Inner encrypted message contained within a Core request 
    or response.

    """
    def __init__(self, data:dict, message_type:Union[PROTO_CORE_GET_REQ,PROTO_CORE_GET_RES,PROTO_CORE_PUT_REQ,PROTO_CORE_PUT_RES,PROTO_CORE_REG_REQ,PROTO_CORE_REG_RES,PROTO_CORE_VERIFY_REQ,PROTO_CORE_VERIFY_RES]):
        """Initialise the message with a dictionary of data and
        a message_type that will determine what fields should be in 
        this inner message. The message_type must be one of hte PROTOC_CORE
        message types

        Args:
            data (dict): data to initialise with
            message_type (Union[PROTO_CORE_GET_REQ,PROTO_CORE_GET_RES,PROTO_CORE_PUT_REQ,PROTO_CORE_PUT_RES,PROTO_CORE_REG_REQ,PROTO_CORE_REG_RES,PROTO_CORE_VERIFY_REQ,PROTO_CORE_VERIFY_RES]): message type
        """
        super().__init__(data)
        self.fields = message_type
        self.signature_fields = message_type
        self.state = WSS_KEP_STATE.EMPTY
        self._data = data

    @classmethod
    def parse(cls, msg:dict)->'ProtocolMessage':
        """We override the parse method of ProtocolMessage in order to
        provide type specific message validation and parsing. This
        message is unusual in that it has multiple type

        Args:
            msg (dict): data to parse

        Returns:
            ProtocolMessage: initialise ProtoMsgCoreEncMsg or None
        """
        if "type" not in msg:
            return None
        type = msg["type"]
        message_type = None
        if type == "Get":
            if PROTO_CORE_GET_REQ.DESC.value in msg:
                message_type=PROTO_CORE_GET_REQ
            else:
                message_type=PROTO_CORE_GET_RES
                
        elif type == "Put":
            if PROTO_CORE_PUT_REQ.DESC.value in msg:
                message_type=PROTO_CORE_PUT_REQ
            else:    
                message_type=PROTO_CORE_PUT_RES
            
                
        elif type == "Reg":
            if PROTO_CORE_REG_REQ.DESC.value in msg:
                message_type=PROTO_CORE_REG_REQ
            else:
                message_type=PROTO_CORE_REG_RES
                
        elif type == "Verify":
            if PROTO_CORE_VERIFY_REQ.DESC.value in msg:
                message_type=PROTO_CORE_VERIFY_REQ
            else:
                message_type=PROTO_CORE_VERIFY_RES
                
        else:
            return None
        
        temp_obj = cls(msg, message_type)
        if temp_obj._validate():
            return temp_obj
        else:
            return None

    
    @staticmethod
    def create_msg_data(message_type:Union[PROTO_CORE_GET_REQ,PROTO_CORE_GET_RES,PROTO_CORE_PUT_REQ,PROTO_CORE_PUT_RES,PROTO_CORE_REG_REQ,PROTO_CORE_REG_RES,PROTO_CORE_VERIFY_REQ,PROTO_CORE_VERIFY_RES],additional_data:dict):
        data = {}
        if issubclass(message_type, PROTO_CORE_GET_REQ) or issubclass(message_type,PROTO_CORE_GET_RES):
            data[message_type.TYPE.value]="Get"
        elif issubclass(message_type, PROTO_CORE_PUT_REQ) or issubclass(message_type, PROTO_CORE_PUT_RES):
            data[message_type.TYPE.value]="Put"
        elif issubclass(message_type, PROTO_CORE_REG_REQ) or issubclass(message_type, PROTO_CORE_REG_RES):
            data[message_type.TYPE.value]="Reg"
        elif issubclass(message_type, PROTO_CORE_VERIFY_REQ) or issubclass(message_type, PROTO_CORE_VERIFY_RES):
            data[message_type.TYPE.value]="Verify"
        for field in message_type:
            if field.value in additional_data:
                data[field.value]=additional_data[field.value]
        data[message_type.SIGNATURE_MSG.value]=""
        return data        


#*************************************************************************
# Error Message Classes
#*************************************************************************
class ProtoErrorMsg(AESGCMEncryptedMessage):
    """Encrypted error message to be sent by a remote client if for
    example it cannot fulfil the request or the user rejects the
    request. This wraps the inner ProtoErrorEncMsg that contains the 
    actual error message
    """
    def __init__(self, data:dict):
        """initialise a new ProtoErrorMsg

        Args:
            data (dict): data to initialise with
        """
        super().__init__(data)
        self.fields = PROTO_CORE# sub_message
        self.state = WSS_KEP_STATE.CORE_RESP
        self._data = data

    @staticmethod
    def create_msg_data(enc_msg:AESGCMEncryptedMessage):
        data = {}
        data[PROTO_CORE.ENC_MSG.value]=enc_msg.get_data()
        return data
    
    def get_encrypted_data(self)->str:
        """Gets the encrypted message blob

        Returns:
            str: JSON string containing IV and cipher text
        """
        return self._data[PROTO_CORE.ENC_MSG.value]

class ProtoErrorEncMsg(SignatureMessage):
    """Inner encrypted error message that contains the 
    actual error message

    """
    def __init__(self, data:dict):
        """initialise a new ProtoErrorEncMsg

        Args:
            data (dict): data to initialise with
        """
        super().__init__(data)
        self.fields = ERROR_MESSAGE
        self.signature_fields = ERROR_MESSAGE
        self.state = WSS_KEP_STATE.EMPTY
        self._data = data
    
    @staticmethod
    def create_msg_data(type:str, error_condition:str):
        data = {}
        data[ERROR_MESSAGE.TYPE.value]=type
        data[ERROR_MESSAGE.ERROR_CONDITION.value]=error_condition
        return data        


#*************************************************************************
# Concrete Protocol Classes
#*************************************************************************

class EnrolmentProtocol(STSDHKEwithAESGCMEncrypedMessageProtocol):
    """Enrolment Protocol that is used to enrol a new device with the
    requester and exchange public identity keys. This protocol will
    be run across two channels, firstly the QRCode to start and then
    will switch the Web Socket Server
    """
    def __init__(self, identity_store:IdentityStore):
        """Initialise the Enrolment protocol providing the IdentityStore
        to use for key retrieval and storage

        Args:
            identity_store (IdentityStore): identity store to retrieve requester keys 
                 from and store repliers keys in
        """
        super().__init__()
        #Set possible message states
        self.states = ENROL_KEP_STATE
        #Start idle/empty
        self.current_state = self.states.EMPTY

        #Define the messages that make up this protocol and their order
        self.protocol_messages.extend([ProtoMsgInitKeyReq,ProtoMsgInitKeyResp,ProtoMsgConfirmKeyMsg])
        
        self.identity_store = identity_store        
        
        self.my_private_key = self.identity_store.get_private_key()
        self.my_public_key_str = self.identity_store.get_public_key_encoded_str()
        self.my_id = self.identity_store.get_public_key_id()
        self.my_name = self.identity_store.get_id()
        self.their_name = None
        self.their_public_key = None
        self.ephe_address_remote = None
    


    def process_outgoing_message(self, message:ProtocolMessage):
        """Process the outgoing message, contains message specific logic and
        calls. The received ProtocolMessage will be initialised by incomplete,
        it may require actions to be performed on it or additional data
        to be added to it.
        
        For example, if a ProtoMsgInitKeyReq is outgoing we must
        first generate an ephemeral key pair and then include the public portion
        in the message.

        This should contain relatively little logic, in that it should just
        be adding data and where necessary making calls the superclass protocols
        to generate data.

        TODO review this approach, the Java implementation of the protocol has adopted
        included the notion of Protocol Data that is passed around and then included
        a LoadData and StoreData interface to allow most of the code in here to 
        be defined by fields within the message classes. Could review which is the
        preferred approach.

        """
        if isinstance(message,ProtoMsgInitKeyReq):
            self.generate_secret()
            message._data[PROTO_ENROL_INIT_KEY_REQ.G_X.value] = self.get_my_ephe_public_key_string()
            message._data[PROTO_ENROL_INIT_KEY_REQ.PC_PUBLIC_KEY.value]=self.my_public_key_str
        if isinstance(message,ProtoMsgInitKeyResp):
            message._data[PROTO_INIT_KEY_RESP.G_Y.value] = self.get_my_ephe_public_key_string()
        if isinstance(message,ProtoMsgInitKeyRespEncMsg):
            message._data[PROTO_ENROL_INIT_KEY_RESP_ENC_MSG.CD_PUBLIC_KEY.value] = self.my_public_key_str
            message._data[PROTO_ENROL_INIT_KEY_RESP_ENC_MSG.ID_CD.value] = self.my_name
            
        #This should go last to ensure auto data has been added
        if isinstance(message,SignatureMessage):
            if isinstance(message,ProtoMsgInitKeyRespEncMsg):
                message.sign_message(self.my_private_key,None,{PROTO_ENROL_INIT_KEY_RESP_SIG.G_Y.value:self.get_my_ephe_public_key_string(),PROTO_ENROL_INIT_KEY_RESP_SIG.G_X.value:self.get_their_ephe_public_key_string()})
            elif isinstance(message,ProtoMsgConfirmKeyEncMsg):
                message.sign_message(self.my_private_key,None,{PROTO_ENROL_INIT_KEY_RESP_SIG.G_Y.value:self.get_their_ephe_public_key_string(),PROTO_ENROL_INIT_KEY_RESP_SIG.G_X.value:self.get_my_ephe_public_key_string()})
            
            else:
                message.sign_message(self.my_private_key)
            
    def process_incoming_message(self, message:ProtocolMessage):
        """Process the incoming message, contains message specific logic and
        calls. The received ProtocolMessage will have been parsed and
        initialised and therefore we can safely assume it contains all fields
        that a particular messsage of that type should have. 
        
        Most of the logic in this method is storing data within the protocol
        object. Much like the above TODO, we should consider adopting the
        Java implementation approach with a StoreData superclass and defining
        data storage in a generic Protocol Data object.

        One essential function this does provide is in performing signature
        verification on inner encrypted messages, this is necessary because the inner
        message has to be initialised and processed in this function and therefore
        hasn't been verified up until this point.
        
        Raises:
            ProtocolException: If signature verification fails on an inner encrypted
                message
        """
        if isinstance(message,ProtoMsgInitKeyReq):
            self.generate_secret()
            self.receive_their_public_key(message.get_ephe_public_key())
            self.their_name = message.get_name()
            self.ephe_address_remote = message.get_ephe_remote_addr()
            self.identity_store.set_public_identity(message.get_name(),message.get_public_identity())
        if isinstance(message,ProtoMsgInitKeyResp):
            self.receive_their_public_key(message.get_ephe_public_key())
            init_key_resp = ProtoMsgInitKeyRespEncMsg.parse(self.decrypt_json_message(message.get_encrypted_data()))
            self.ephe_address_remote = init_key_resp.get_ephe_remote_addr()
            self.identity_store.set_public_identity(init_key_resp.get_name(),init_key_resp.get_public_identity())
            self.their_public_key = CryptoUtils.load_public_key_from_string(init_key_resp.get_public_identity())
            self.their_name = init_key_resp.get_name()
            if not init_key_resp.verify_signature(self.their_public_key,None,{PROTO_ENROL_INIT_KEY_RESP_SIG.G_X.value:self.get_my_ephe_public_key_string(),PROTO_ENROL_INIT_KEY_RESP_SIG.G_Y.value:self.get_their_ephe_public_key_string()}):
                raise ProtocolException("Signature verification failed")
        if isinstance(message,SignatureMessage):
            if isinstance(message,ProtoMsgConfirmKeyEncMsg):
                if not message.verify_signature(self.their_public_key,None,{PROTO_ENROL_INIT_KEY_RESP_SIG.G_X.value:self.get_their_ephe_public_key_string(),PROTO_ENROL_INIT_KEY_RESP_SIG.G_Y.value:self.get_my_ephe_public_key_string()}):
                    raise ProtocolException("Signature verification failed")
            else:
                message.verify_signature(self.identity_store.get_public_identity_from_key_id(message.get_sender_public_key_id()))

class WSSKeyExchangeProtocol(STSDHKEwithAESGCMEncrypedMessageProtocol):
    """WebSocketServer key exchange protocol. This is the basis for all Core
    protocol messages (GET, PUT, REG, Verify). Similar to the enrol protocol
    this will be run across more than one channel. The initial request is sent
    as a Push notification before both parties switch to using the WebSocketServer
    as a relay.

    """
    def __init__(self, identity_store:IdentityStore, target_id:str=None):
        """Initialise the web socket protocol with the specified IdentityStore
        to use for key retrieval and storage. 

        Args:
            identity_store (IdentityStore): IdentityStore to use for key retrieval and storage  
            target_id (str, optional): If known specify the target ID, otherwise this will be 
                filled by the incoming message. Defaults to None.
        """
        super().__init__()
        self.states = WSS_KEP_STATE
        self.target_id = target_id
        self.current_state = self.states.EMPTY
        self.protocol_messages.extend([ProtoWSSInitKeyReqMsg,ProtoMsgInitKeyResp,ProtoMsgConfirmKeyMsg,ProtoMsgCoreMsg,ProtoMsgCoreRespMsg])
        
        self.identity_store = identity_store
        
        self.my_private_key = self.identity_store.get_private_key()
        self.my_id = self.identity_store.get_public_key_id()
        self.my_name = self.identity_store.get_id()
        self.their_id = None
        self.ephe_address_remote = None
        self.core_request = None
    
    def get_target_id(self)->str:
        """Gets the target id

        Returns:
            str: target ID
        """
        return self.target_id
    
    def get_core_request(self)->dict:
        """Get the underlying data object that was included in the
        inner encrypted message. Call this to retrieve data from
        the request, like challenge nonces or encrypted data from
        a PUT

        Returns:
            dict: inner JSON dictionary of message data
        """
        return self.core_request

    def get_target_public_identity(self)->str:
        """Gets the public key associated with the target id

        Returns:
            str: Base64 encoded public key
        """
        return self.identity_store.get_public_identity_from_key_id(self.target_id)

    def process_outgoing_message(self, message:ProtocolMessage):
        """Process the outgoing message, adding data to it where needed

        Args:
            message (ProtocolMessage): Protocol message to process
        """
        if isinstance(message,ProtoWSSInitKeyReqMsg):
            self.generate_secret()
            message._data[PROTO_WSS_INIT_KEY_REQ.G_X.value] = self.get_my_ephe_public_key_string()
            message._data[PROTO_WSS_INIT_KEY_REQ.HASH_PC_PUBLIC_KEY.value]=self.my_id
        if isinstance(message,ProtoMsgInitKeyResp):
            message._data[PROTO_INIT_KEY_RESP.G_Y.value] = self.get_my_ephe_public_key_string()
        if isinstance(message,ProtoWSSInitKeyRespEncMsg):
            message._data[PROTO_WSS_INIT_KEY_RESP_ENC_MSG.HASH_CD_PUBLIC_KEY.value] = self.my_id
            
        #This should go last to ensure auto data has been added
        if isinstance(message,SignatureMessage):
            if isinstance(message,ProtoWSSInitKeyRespEncMsg):
                message.sign_message(self.my_private_key,None,{PROTO_ENROL_INIT_KEY_RESP_SIG.G_Y.value:self.get_my_ephe_public_key_string(),PROTO_ENROL_INIT_KEY_RESP_SIG.G_X.value:self.get_their_ephe_public_key_string()})
            elif isinstance(message,ProtoMsgConfirmKeyEncMsg):
                message.sign_message(self.my_private_key,None,{PROTO_ENROL_INIT_KEY_RESP_SIG.G_Y.value:self.get_their_ephe_public_key_string(),PROTO_ENROL_INIT_KEY_RESP_SIG.G_X.value:self.get_my_ephe_public_key_string()})
            else:
                message.sign_message(self.my_private_key)
            
    def process_incoming_message(self, message:ProtocolMessage):
        """Process the incoming message. This is where most of the message
        processing logic is contained.

        Args:
            message (ProtocolMessage): protocol message to process

        Raises:
            ProtocolException: thrown if IDs do not match or signature verification fails
            ProtocolRemoteException: thrown if a remote error message is received
        """
        if isinstance(message,ProtoWSSInitKeyReqMsg):
            self.generate_secret()
            self.receive_their_public_key(message.get_ephe_public_key())
            self.their_id = message.get_sender_public_key_id()
            #we set the target_id based on who initialised the request
            self.target_id = self.their_id
            
            self.ephe_address_remote = message.get_ephe_remote_addr()
        if isinstance(message,ProtoMsgInitKeyResp):
            self.receive_their_public_key(message.get_ephe_public_key())
            init_key_resp = ProtoWSSInitKeyRespEncMsg.parse(self.decrypt_json_message(message.get_encrypted_data()))
            self.ephe_address_remote = init_key_resp.get_ephe_remote_addr()
            self.their_id = init_key_resp.get_sender_public_key_id()
            print(self.their_id + ":" + self.target_id)
            if self.their_id!=self.target_id:
                raise ProtocolException("Inconsistent IDs, target and response do not match")
            #We use the target ID because they should be responding with the ID we expected
            temp_key = self.identity_store.get_public_identity_from_key_id(self.target_id)
            if not init_key_resp.verify_signature(temp_key,None,{PROTO_ENROL_INIT_KEY_RESP_SIG.G_X.value:self.get_my_ephe_public_key_string(),PROTO_ENROL_INIT_KEY_RESP_SIG.G_Y.value:self.get_their_ephe_public_key_string()}):
                raise ProtocolException("Signature verification failed")
        if isinstance(message,ProtoMsgCoreMsg):
            msg = self.decrypt_json_message(message.get_encrypted_data())
            if "error-condition" in msg:
                json_error_msg = json.loads(msg["error-condition"])
                raise ProtocolRemoteException(json_error_msg["error-code"],json_error_msg["error-message"])
            core_req = ProtoMsgCoreEncMsg.parse(msg)
            if not core_req.verify_signature(self.identity_store.get_public_identity_from_key_id(self.their_id),None):
                raise ProtocolException("Signature verification failed")
            self.core_request = core_req.get_data()
        if isinstance(message,ProtoMsgCoreRespMsg):
            msg =self.decrypt_json_message(message.get_encrypted_data())
            if "error-condition" in msg:
                core_req = ProtoErrorEncMsg.parse(msg)
                if not core_req.verify_signature(self.identity_store.get_public_identity_from_key_id(self.their_id),None):
                    raise ProtocolException("Signature verification failed")
                self.core_request = core_req.get_data()
                error_condition = json.loads(self.core_request["error-condition"])
                raise ProtocolRemoteException(error_condition["error-code"],error_condition["error-message"])
                
            core_req = ProtoMsgCoreEncMsg.parse(msg)
            if not core_req.verify_signature(self.identity_store.get_public_identity_from_key_id(self.their_id),None):
                raise ProtocolException("Signature verification failed")
            self.core_request = core_req.get_data()
            
        if isinstance(message,SignatureMessage):
            if isinstance(message,ProtoMsgConfirmKeyEncMsg):
                if not message.verify_signature(self.identity_store.get_public_identity_from_key_id(self.their_id),None,{PROTO_ENROL_INIT_KEY_RESP_SIG.G_X.value:self.get_their_ephe_public_key_string(),PROTO_ENROL_INIT_KEY_RESP_SIG.G_Y.value:self.get_my_ephe_public_key_string()}):
                    raise ProtocolException("Signature verification failed")
            else:
                message.verify_signature(self.identity_store.get_public_identity_from_key_id(message.get_sender_public_key_id()))                
            



