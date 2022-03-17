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
import threading
import time
from cgi import test
from enum import Enum
from subprocess import call
from tkinter.messagebox import NO
from typing import List, Union

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          PublicFormat)

from compendium.protocol import (PROTO_CORE_GET_REQ, PROTO_CORE_GET_RES,
                                 PROTO_CORE_PUT_REQ, PROTO_CORE_PUT_RES,
                                 PROTO_CORE_REG_REQ, PROTO_CORE_REG_RES,
                                 PROTO_CORE_VERIFY_REQ, PROTO_CORE_VERIFY_RES,
                                 WSS_KEP_STATE, EnrolmentProtocol,
                                 ProtocolRemoteException,
                                 ProtoMsgConfirmKeyEncMsg,
                                 ProtoMsgConfirmKeyMsg, ProtoMsgCoreEncMsg,
                                 ProtoMsgCoreMsg, ProtoMsgCoreRespMsg,
                                 ProtoMsgInitKeyReq, ProtoMsgInitKeyResp,
                                 ProtoMsgInitKeyRespEncMsg,
                                 ProtoWSSInitKeyReqMsg,
                                 ProtoWSSInitKeyRespEncMsg,
                                 WSSKeyExchangeProtocol)
from compendium.storage import (CombinedIdentityStore, IdentityStore,
                                KeyRingIdentityStore)
from compendium.ui import UI
from compendium.utils import B64, CryptoUtils
from compendium.wss.client import (INITRESP, TYPE, Message, WssClient,
                                   WssClientListener)
from compendium.wss.message import DELIVER

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler(sys.stdout)
logger.addHandler(streamHandler)

#Push server constants
PUSH_SERVER_ADDRESS="https://compendium.dev.castellate.com"
PUSH_SERVER_PORT=4500
PUSH_PATH = "/pushmessage"

class CompendiumException(Exception):
    """Generic exception wrapper
    """
    pass

class PC_MODE(Enum):
    """Represents the MODE of the PC, either not running a protocol,
    running the ENROL protocol or running the WSS protocol. This 
    determines how it treats some of the responses.
    """
    IDLE=0
    ENROL = 1
    WSS = 2
class PC(WssClientListener):
    """Core PC class that implements the WssClientListener interface. This
    provides the link between the Compendium class and the underlying
    Web Socket Client
    """
    def __init__(self, identity_store:IdentityStore=KeyRingIdentityStore()):
        """Creates a new instance of PC to be used to call and process the various
        protocol implementations.

        Args:
            identity_store (IdentityStore, optional): If set this overrides the underlying
                IdentityStore. A caller should subclass IdentityStore to manage their own
                credentials rather than using the system wide shared storage.
                Defaults to KeyRingIdentityStore().
        """
        self.identity_store = identity_store
        self.ephe_wss_addr_local = None
        self.client = None
        self.current_protocol = None
        self.mode = PC_MODE.IDLE
        self.core_protocol = None
        self.core_protocol_data = None
        self.callback = None
        self.qr_monitor = None
        
        
    def qr_callback(self,res):
        """Receives callback from QRCode Monitor if the screen is closed

        Currently this is just logged. TODO react to closing of window  

        Args:
            res (Any): response code
        """
        logger.debug("qrcallback:%s", res)    

    def get_key_from_name(self, name:str)->str:
        """Wrapper function to get the Base64 encoded public key of the
        device with the specified name

        Args:
            name (str): name of device

        Returns:
            str: Base64 encoded public key
        """
        return self.identity_store.get_public_identity_str_from_name(name)
    def get_key_id_from_name(self, name:str)->str:
        """Gets the Public Key ID from the device name

        Args:
            name (str): name of the device

        Returns:
            str: Base64 encoded Public Key ID (SHA256 has of public key bytes)
        """
        return self.identity_store.get_public_key_id_from_name(name)
    def get_key_names(self):
        """Gets a list of currently stored key names

        Returns:
            list: List of device names
        """
        return self.identity_store.get_key_names()
    
    def get_key_ids(self):
        """Gets the stored key IDs

        Returns:
            list: Base64 encoded key IDs
        """
        return self.identity_store.get_key_ids()

    def ws_received(self, msg: Message):
        """Processes a received Web Socket message

        Args:
            msg (Message): received message
        """
        if msg.get_type() is TYPE.INITRESP:
            #This is a INIT resp and contains our assigned address
            self.ephe_wss_addr_local=msg[INITRESP.ADR.value]
            logger.debug("Set client address:%s",self.ephe_wss_addr_local)
            msg_one = self.current_protocol.prepare_outgoing_msg(self.current_protocol.get_next_message_class().create_msg_data(self.ephe_wss_addr_local))
            if self.mode == PC_MODE.ENROL:
                #If we are in enrol we now need to show the QRCode
                self.qr_monitor = UI.show_qr_screen_new_process(msg_one.get_string(),self.qr_callback)
            elif self.mode == PC_MODE.WSS:
                #If we are in WSS we send the first message via the Push Server
                self.send_push_notification(CryptoUtils.public_key_to_string(self.current_protocol.get_target_public_identity()),msg_one.get_data())
                                
        elif msg.get_type() is TYPE.DELIVER:
            #It's a DELIVER message indicating it is from a companion device
            logger.debug("Delivered:%s",msg)
            if "Error" in msg:
                #Check if it is an error first
                logger.error("ErrorMessage received: %s",json.dumps(msg))
                self._handle_error(ProtocolRemoteException(msg["Error"]["error-code"],msg["Error"]["error-message"]))
                return
            #If we got here it is not a plaintext error message, so try to process it using the current protocol
            try:
                response = self.current_protocol.parse_incoming_msg(msg.get_field_value(DELIVER.MSG.value))
            except ProtocolRemoteException as error:
                #This will fire if it was encrypted error message
                self._handle_error(error)
                return
            #If we got here then it isn't an error message
            if response is not None:
                #Check we have accepted the message - i.e. it was of the correct form 
                #for the next message, otherwise response will be None
                if self.mode == PC_MODE.ENROL:
                    self._process_key_response()
                elif self.mode == PC_MODE.WSS:
                    logger.debug(response)
                    if self.current_protocol.current_state == WSS_KEP_STATE.INIT_KEY_RESP:
                        self._process_key_response()
                        time.sleep(0.5)#TODO improve this, we add a delay to reduce the chance of message ordering problems
                        self._process_core_request()
                    elif self.current_protocol.current_state == WSS_KEP_STATE.CORE_REQ:
                        logger.error("Received a message we shouldn't receive: %s",response)
                    elif self.current_protocol.current_state == WSS_KEP_STATE.CORE_RESP:
                        logger.debug("Received a CORE response: %s", response)                        
                        if self.callback is not None:
                            logger.debug("Firing callback")
                            (threading.Thread(target=self.callback,args=(self.current_protocol.get_core_request(),),daemon=True)).start()                            
                        logger.debug("Will call close on the web socket client")
                        self.client.close()
        else:
            logger.debug("Received:%s",msg)

    def reset(self):
        """Resets the PC and underlying web socket client so it can be 
        reused for another protocol run
        """
        if self.client is not None:
            self.client.close()
        self.ephe_wss_addr_local = None
        self.client = None# WssClient()
        self.current_protocol = None
        self.mode = PC_MODE.IDLE
        self.core_protocol = None
        self.core_protocol_data = None
        

    def _handle_error(self, error):
        """Handle an error, sending it to the relevant
        callback if there is one available

        Args:
            error (Any): Error 

        Raises:
            error: re-raises the error if no callback is available
        """
        if self.callback is not None:            
            self.callback(None,error)
            self.reset()
        else:
            raise error

    def _process_key_response(self):
        """Handles the response to the initial key request message

        If this is an enrol protocol we close the QRCode window since we have
        now initialised a connection to the companion device.
        """
        #PC Prepares confirmation message
        #Create inner signature to be encrypted
        encrypted_confirm_signature = ProtoMsgConfirmKeyEncMsg.parse(ProtoMsgConfirmKeyEncMsg.create_msg_data())
        self.current_protocol.process_outgoing_message(encrypted_confirm_signature)

        #Create encrypted message wrapper
        enc_msg = ProtoMsgConfirmKeyMsg.create_encrypted_json_msg(encrypted_confirm_signature.get_data(),self.current_protocol.derived_key)
        confirm_message = self.current_protocol.prepare_outgoing_msg(ProtoMsgConfirmKeyMsg.create_msg_data(enc_msg))
        if self.mode == PC_MODE.ENROL:
            self.client.set_close_after_send()
            if self.qr_monitor is not None:
                self.qr_monitor.close()
        self.client.send(Message.create_route(self.current_protocol.ephe_address_remote,confirm_message.get_data()))
        if self.mode == PC_MODE.ENROL:
            if self.callback is not None:
                (threading.Thread(target=self.callback,args=({"type":"enrol","CD_id":self.current_protocol.their_name},),daemon=True)).start()
            

    def _process_core_request(self):
        """Process a core request or response, this will be one of the
        core functions, GET, PUT, Reg, Verify
        """
        #ProtoMsgCoreEncMsg, ProtoMsgCoreRespMsg, ProtoMsgCoreMsg
        core_msg = ProtoMsgCoreEncMsg.parse(ProtoMsgCoreEncMsg.create_msg_data(self.core_protocol,self.core_protocol_data))
        self.current_protocol.process_outgoing_message(core_msg)

        #Create encrypted message wrapper
        wrapper_msg = ProtoMsgCoreMsg.create_encrypted_json_msg(core_msg.get_data(),self.current_protocol.derived_key)
        confirm_message = self.current_protocol.prepare_outgoing_msg(ProtoMsgCoreMsg.create_msg_data(wrapper_msg))
        self.client.send(Message.create_route(self.current_protocol.ephe_address_remote,confirm_message.get_data()))


    def start_enrolment(self,callback):
        """Start the enrolment process and call callback once it is finished

        Args:
            callback (function): callback to call when enrolment is complete

        Raises:
            CompendiumException: thrown if an error occurs during enrolment
        """
        if self.mode is not PC_MODE.IDLE:
            raise CompendiumException("Cannot run two protocols at once")
        self.client = WssClient()
        self.callback = callback
        self.current_protocol = EnrolmentProtocol(self.identity_store)
        self.mode = PC_MODE.ENROL
        self.client.connect()
        self.client.add_listener(self)
        self.client.send(Message.create_init())
    
    def start_wss(self, key_id:str, core_protocol:Union[PROTO_CORE_GET_REQ,PROTO_CORE_PUT_REQ,PROTO_CORE_REG_REQ,PROTO_CORE_VERIFY_REQ], core_protocol_data,callback):
        """Start the Web Socket protocol, this is the main protocol for performing the
        GET, PUT, Reg, Verify

        Args:
            key_id (str): Base64 Public Key ID of target
            core_protocol (Union[PROTO_CORE_GET_REQ,PROTO_CORE_PUT_REQ,PROTO_CORE_REG_REQ,PROTO_CORE_VERIFY_REQ]): The sub protocol that should be started
            core_protocol_data (dict): existing protocol data, for example, data that will be needed to complete the protocol run
            callback (function): callback to call when the function completes or has an error

        Raises:
            CompendiumException: _description_
        """
        if self.mode is not PC_MODE.IDLE:
            raise CompendiumException("Cannot run two protocols at once")
        self.client = WssClient()
        self.callback = callback
        self.core_protocol=core_protocol
        self.core_protocol_data = core_protocol_data
        self.current_protocol = WSSKeyExchangeProtocol(self.identity_store,key_id)
        self.mode = PC_MODE.WSS
        self.client.connect()
        self.client.add_listener(self)
        self.client.send(Message.create_init())
        

    def send_push_notification(self,target_id:str,content:dict):
        """Sends a push notification via the Push Server

        This runs on a separate thread to avoid blocking

        Args:
            target_id (str): Base64 encoded public key of target
            content (dict): data to send
        """
        t = threading.Thread(target=self._request_sender,daemon=True, args=(target_id,content,self.push_request_response))
        t.start()
    
    def push_request_response(self, response):
        """Response from the push request

        Args:
            response (Response): response object from the requests
        """
        logger.debug("Response to push request: %d",response.status_code)
    
    def _request_sender(self, target_id:str, content:dict,callback):
        """Sends a push request to the PushServer, this should be called
        on a new thread to avoid blocking

        TODO externalise strings
        Args:
            target_id (str): Base64 Public Key
            content (dict): data to be sent
            callback (function): callback to call when request receives a response
        """
        msg = {}
        msg["msg"]=content
        msg["pub_key"]=target_id
        
        web_address = PUSH_SERVER_ADDRESS
        if(not PUSH_SERVER_PORT ==""):
            web_address = web_address + ":" + str(PUSH_SERVER_PORT)
        web_address = web_address + PUSH_PATH
        callback(requests.post(web_address,json=msg, timeout=30))
        


class Compendium():
    """Main interface to the Compendium library. This is the class that
    requester apps should instantiate in order to interact with the library.
    """
    def __init__(self, identity_store:IdentityStore=None):
        """Create a new instance of Compendium. If a requester wish to override the
        default system wide keystore is should subclass IdentityStore and pass a
        reference to it here

        Args:
            identity_store (IdentityStore, optional): Subclass of IdentityStore to override system wide keystore. Defaults to None.
        """
        self.pc = None
        if identity_store is not None:
            self.pc = PC(identity_store)
        else:
            self.pc = PC()
        assert(self.pc is not None)
    
    def reset(self):
        """Resets the compendium protocol to allow it to be reused
        """
        self.pc.reset()
    def get_enrolled_devices(self):
        """Gets a list of enrolled device names

        Returns:
            list: list of string device names
        """
        return [*self.pc.get_key_names()]

    def enrol_new_device(self, callback):
        """Enrol a new device and wait for callback response

        This will show a QRCode for the new device to scan

        Args:
            callback (function): callback to call when enrolment is complete
        """
        self.pc.start_enrolment(callback)

    def register_user_verification(self, companion_name:str, app_id:str, description:str,callback):
        """Requests to register the APPID for user verification

        Args:
            companion_name (str): device name to make the request to
            app_id (str): APPID of requester, this must be unique within the 
                            PC-Device relationship and must not be the same 
                            as an APPID for another purpose, i.e. Put or Get
            description (str): Description of why the request is being made, 
                             will be displayed to user on Companion Device
            callback (function): callback to call when registration completes
        """
        #TODO handle name clashes
        key = self.pc.get_key_id_from_name(companion_name)
        data = {}
        data[PROTO_CORE_REG_REQ.APP_ID.value]=app_id
        data[PROTO_CORE_REG_REQ.DESC.value]=description
        data[PROTO_CORE_REG_REQ.ID_CD.value]=key
        self.pc.start_wss(key,PROTO_CORE_REG_REQ,data,callback)

    def perform_user_verification(self, companion_name:str, app_id:str, description:str, code:str, callback, nonce:bytes=None)->bytes:
        """Perform a user verification request
        
        If a challenge nonce is not provided one will be generated

        Args:
            companion_name (str): name of target device to make the request to
            app_id (str): APPID the user verification key was registered under
            description (str): Description of why a user verification is requested, 
                            will be displayed to the user on the Companion Device
            code (str): Security code that will be displayed on both PC and 
                        Companion Device for comparison
            callback (function): callback to call once complete
            nonce (bytes, optional): custom challenge nonce, if None one will be generated. Defaults to None.

        Returns:
            bytes: _description_
        """ 
        #TODO handle name clashes
        key = self.pc.get_key_id_from_name(companion_name)
        data = {}
        if nonce is None:
            nonce=os.urandom(12)
        data[PROTO_CORE_REG_REQ.APP_ID.value]=app_id
        data[PROTO_CORE_VERIFY_REQ.DESC.value]=description
        data[PROTO_CORE_VERIFY_REQ.ID_CD.value]=key
        data[PROTO_CORE_VERIFY_REQ.CODE.value]=code
        data[PROTO_CORE_VERIFY_REQ.NONCE.value]=B64.encode(nonce)
        self.pc.start_wss(key,PROTO_CORE_VERIFY_REQ,data,callback)
        return nonce
    
    def put_data(self,data_to_send:bytes, companion_name:str, app_id:str, description:str, code:str, callback):
        """Passes the specified data to the Companion Device for it to 
        be encrypted and returns the encrypted blob for storage locally

        Args:
            data_to_send (bytes): data to send, must be bytes, even if just a string
            companion_name (str): device name to make the request to
            app_id (str): APPID to register the encryption key under, must be unique
                        within the PC - Device relationship and must not be the same
                        as an existing APPID for a different purpose
            description (str): Description of why the request is being made
            code (str): Security code that will be displayed on PC and Companion Device
            callback (function): Callback to call once complete
        """ 
        key = self.pc.get_key_id_from_name(companion_name)
        data = {}    
        data[PROTO_CORE_PUT_REQ.APP_ID.value]=app_id
        data[PROTO_CORE_PUT_REQ.DESC.value]=description
        data[PROTO_CORE_PUT_REQ.ID_CD.value]=key
        data[PROTO_CORE_PUT_REQ.CODE.value]=code
        data[PROTO_CORE_PUT_REQ.DATA.value]=B64.encode(data_to_send)
        self.pc.start_wss(key,PROTO_CORE_PUT_REQ,data,callback)

    def get_data(self,encrypted_data:dict, companion_name:str, app_id:str, description:str, code:str, callback):
        """Sends an encrypted blob to the Companion Device to have
        it decrypted and the plaintext returned

        Args:
            encrypted_data (dict): Encrypted data blob in the form of a JSON object
            companion_name (str): device name to send the request to
            app_id (str): APPID the encryption key was created under
            description (str): description of why the request is being made
            code (str): security code that will be displayed on the PC and Device
            callback (function): callback to call once complete
        """
        key = self.pc.get_key_id_from_name(companion_name)
        data = {}
        #This must be set as a string not JSON to ensure the signature verifies
        #enc_data = {"cipher_text":"piCiqNxUabPw8MdvRLoCimYEzf3yb2SBSe2kuOCDZqjSzeg=","iv":"n+NYaNj769D60\/Qh"}
        data[PROTO_CORE_GET_REQ.APP_ID.value]=app_id
        data[PROTO_CORE_GET_REQ.DESC.value]=description
        data[PROTO_CORE_GET_REQ.ID_CD.value]=key
        data[PROTO_CORE_GET_REQ.CODE.value]=code
        data[PROTO_CORE_GET_REQ.ENC_DATA.value]=json.dumps(encrypted_data)
        self.pc.start_wss(key,PROTO_CORE_GET_REQ,data,callback)
    
    @staticmethod
    def verify_signature(signature: str, data:bytes, key:str)->bool:
        """Utility method to allow easy signature verification

        Args:
            signature (str): Base64 encoded signature
            data (bytes): data that was signed
            key (str): Base64 encoded public key to verify against

        Returns:
            bool: True if valid, False if not
        """
        public_key = CryptoUtils.load_public_key_from_string(key)
        try:
            public_key.verify(B64.decode(signature),data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
 