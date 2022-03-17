

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
from compendium.storage import CombinedIdentityStore, IdentityStore, KeyRingIdentityStore
from compendium.ui import UI
from compendium.utils import B64, CryptoUtils
from compendium.wss.client import (INITRESP, TYPE, Message, WssClient,
                                   WssClientListener)
from compendium.wss.message import DELIVER

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler(sys.stdout)
logger.addHandler(streamHandler)

PUSH_SERVER_ADDRESS="https://compendium.dev.castellate.com"
PUSH_SERVER_PORT=4500
PUSH_PATH = "/pushmessage"

class CompendiumException(Exception):
    pass

class PC_MODE(Enum):
    IDLE=0
    ENROL = 1
    WSS = 2
class PC(WssClientListener):

    def __init__(self, identity_store:CombinedIdentityStore=KeyRingIdentityStore()):
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
        print("qrcallback:" + res)    

    def get_key_from_name(self, name:str)->str:
        return self.identity_store.get_public_identity_str_from_name(name)
    def get_key_id_from_name(self, name:str)->str:
        return self.identity_store.get_public_key_id_from_name(name)
    def get_key_names(self):
        return self.identity_store.get_key_names()
    
    def get_key_ids(self):
        return self.identity_store.get_key_ids()

    def ws_received(self, msg: Message):
        if msg.get_type() is TYPE.INITRESP:
            self.ephe_wss_addr_local=msg[INITRESP.ADR.value]
            logger.debug("Set client address:%s",self.ephe_wss_addr_local)
            msg_one = self.current_protocol.prepare_outgoing_msg(self.current_protocol.get_next_message_class().create_msg_data(self.ephe_wss_addr_local))
            if self.mode == PC_MODE.ENROL:
                #showQRCode
                self.qr_monitor = UI.show_qr_screen_new_process(msg_one.get_string(),self.qr_callback)
                #cd.receive_qr_code(msg_one.get_string())
                pass
            elif self.mode == PC_MODE.WSS:
                #send as push
                
                self.send_push_notification(CryptoUtils.public_key_to_string(self.current_protocol.get_target_public_identity()),msg_one.get_data())
                #cd.receive_push(msg_one.get_string())
                pass
        elif msg.get_type() is TYPE.DELIVER:
            logger.debug("Delivered:%s",msg)
            if "Error" in msg:
                print("ErrorMessage received:" + json.dumps(msg))
                self._handle_error(ProtocolRemoteException(msg["Error"]["error-code"],msg["Error"]["error-message"]))
                return
            try:
                response = self.current_protocol.parse_incoming_msg(msg.get_field_value(DELIVER.MSG.value))
            except ProtocolRemoteException as error:
                self._handle_error(error)
                return
            if response is not None:
                if self.mode == PC_MODE.ENROL:
                    self._process_key_response()
                elif self.mode == PC_MODE.WSS:
                    print(response)
                    if self.current_protocol.current_state == WSS_KEP_STATE.INIT_KEY_RESP:
                        self._process_key_response()
                        time.sleep(0.5)#TODO improve this, we add a delay to reduce the chance of message ordering problems
                        self._process_core_request()
                    elif self.current_protocol.current_state == WSS_KEP_STATE.CORE_REQ:
                        print("Received Response")
                        print(response)
                    elif self.current_protocol.current_state == WSS_KEP_STATE.CORE_RESP:
                        print("Received CORE response")
                        print(self.callback)
                        if self.callback is not None:
                            (threading.Thread(target=self.callback,args=(self.current_protocol.get_core_request(),),daemon=True)).start()
                            #self.callback(self.current_protocol.get_core_request())
                        print("Calling close on PC")
                        self.client.close()
                        
                        

                #Valid message received
                
            #self.client.close()
        else:
            logger.debug("Received:%s",msg)

    def reset(self):
        if self.client is not None:
            self.client.close()
        self.ephe_wss_addr_local = None
        self.client = None# WssClient()
        self.current_protocol = None
        self.mode = PC_MODE.IDLE
        self.core_protocol = None
        self.core_protocol_data = None
        

    def _handle_error(self, error):
        if self.callback is not None:            
            self.callback(None,error)
            self.reset()
        else:
            raise error

    def _process_key_response(self):
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
        #ProtoMsgCoreEncMsg, ProtoMsgCoreRespMsg, ProtoMsgCoreMsg
        core_msg = ProtoMsgCoreEncMsg.parse(ProtoMsgCoreEncMsg.create_msg_data(self.core_protocol,self.core_protocol_data))
        self.current_protocol.process_outgoing_message(core_msg)

        #Create encrypted message wrapper
        wrapper_msg = ProtoMsgCoreMsg.create_encrypted_json_msg(core_msg.get_data(),self.current_protocol.derived_key)
        confirm_message = self.current_protocol.prepare_outgoing_msg(ProtoMsgCoreMsg.create_msg_data(wrapper_msg))
        self.client.send(Message.create_route(self.current_protocol.ephe_address_remote,confirm_message.get_data()))


    def start_enrolment(self,callback):
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
        t = threading.Thread(target=self._request_sender,daemon=True, args=(target_id,content,self.push_request_response))
        t.start()
    
    def push_request_response(self, response):
        print(response.status_code)
    
    def _request_sender(self, target_id:str, content:dict,callback):
        msg = {}
        msg["msg"]=content
        msg["pub_key"]=target_id
        
        web_address = PUSH_SERVER_ADDRESS
        if(not PUSH_SERVER_PORT ==""):
            web_address = web_address + ":" + str(PUSH_SERVER_PORT)
        web_address = web_address + PUSH_PATH
        callback(requests.post(web_address,json=msg, timeout=30))
        


class Compendium():
    def __init__(self, identity_store:IdentityStore=None):
        self.pc = None
        if identity_store is not None:
            self.pc = PC(identity_store)
        else:
            self.pc = PC()
        assert(self.pc is not None)
    
    def reset(self):
        self.pc.reset()
    def get_enrolled_devices(self):
        return [*self.pc.get_key_names()]

    def enrol_new_device(self, callback):
        self.pc.start_enrolment(callback)

    def register_user_verification(self, companion_name:str, app_id:str, description:str,callback):
        #TODO handle name clashes
        key = self.pc.get_key_id_from_name(companion_name)
        data = {}
        data[PROTO_CORE_REG_REQ.APP_ID.value]=app_id
        data[PROTO_CORE_REG_REQ.DESC.value]=description
        data[PROTO_CORE_REG_REQ.ID_CD.value]=key
        self.pc.start_wss(key,PROTO_CORE_REG_REQ,data,callback)

    def perform_user_verification(self, companion_name:str, app_id:str, description:str, code:str, callback, nonce:bytes=None)->bytes:
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
        key = self.pc.get_key_id_from_name(companion_name)
        data = {}    
        data[PROTO_CORE_PUT_REQ.APP_ID.value]=app_id
        data[PROTO_CORE_PUT_REQ.DESC.value]=description
        data[PROTO_CORE_PUT_REQ.ID_CD.value]=key
        data[PROTO_CORE_PUT_REQ.CODE.value]=code
        data[PROTO_CORE_PUT_REQ.DATA.value]=B64.encode(data_to_send)
        self.pc.start_wss(key,PROTO_CORE_PUT_REQ,data,callback)

    def get_data(self,encrypted_data:dict, companion_name:str, app_id:str, description:str, code:str, callback):
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
        public_key = CryptoUtils.load_public_key_from_string(key)
        try:
            public_key.verify(B64.decode(signature),data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
 