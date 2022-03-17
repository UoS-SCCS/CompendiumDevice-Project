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
from compendium.storage import IdentityStore, KeyRingIdentityStore
from compendium.ui import UI
from compendium.utils import B64, CryptoUtils
from compendium.wss.client import (INITRESP, TYPE, Message, WssClient,
                                   WssClientListener)
from compendium.wss.message import DELIVER


class CD_MODE(Enum):
    IDLE=0
    ENROL = 1
    WSS = 2
class Companion(WssClientListener):
    """This is for testing only and should not be used elsewhere.

    It provides a basic implementation of a companion device to allow
    protocol development. It is not a complete implementation do not
    use for actual companion device implementations. 

    Args:
        WssClientListener (_type_): _description_
    """   
    def __init__(self):
        self.identity_store = KeyRingIdentityStore(service_name="Compendium2")
        self.ephe_wss_addr_local = None
        self.client = WssClient()
        self.current_protocol = None
        self.mode = CD_MODE.IDLE
        self.cryptostore = DummyCryptoStore("dummy_crypto_store.json")

    def ws_received(self, msg: Message):
        if msg.get_type() is TYPE.INITRESP:
            self.ephe_wss_addr_local=msg[INITRESP.ADR.value]
            logger.debug("Set client address:%s",self.ephe_wss_addr_local)
            resp_enc_msg =None
            if self.mode == CD_MODE.ENROL:
                resp_enc_msg = ProtoMsgInitKeyRespEncMsg.parse(ProtoMsgInitKeyRespEncMsg.create_msg_data(self.ephe_wss_addr_local))
            elif self.mode == CD_MODE.WSS:
                resp_enc_msg = ProtoWSSInitKeyRespEncMsg.parse(ProtoWSSInitKeyRespEncMsg.create_msg_data(self.ephe_wss_addr_local))
            self.current_protocol.process_outgoing_message(resp_enc_msg)
            enc_msg = ProtoMsgInitKeyResp.create_encrypted_json_msg(resp_enc_msg.get_data(),self.current_protocol.derived_key)
            
            msg_two = self.current_protocol.prepare_outgoing_msg(self.current_protocol.get_next_message_class().create_msg_data(enc_msg))
            self.client.send(Message.create_route(self.current_protocol.ephe_address_remote,msg_two.get_data()))
        elif msg.get_type() is TYPE.DELIVER:
            logger.debug("Delivered:%s",msg)
            response = self.current_protocol.parse_incoming_msg(msg.get_field_value(DELIVER.MSG.value))
           
            if response is not None:
                print(response)
                if self.current_protocol.current_state == WSS_KEP_STATE.KEY_CONFIRM_REQ:
                    print("key exchange complete")
                elif self.current_protocol.current_state == WSS_KEP_STATE.CORE_REQ:
                    core_req = self.current_protocol.get_core_request()
                    resp_data = {PROTO_CORE_REG_RES.TYPE.value:core_req["type"]}
                    if core_req["type"]=="Reg":
                        veri_key = self.cryptostore.create_verification_key(core_req[PROTO_CORE_REG_REQ.APP_ID.value])
                        resp_data[PROTO_CORE_REG_RES.APP_ID.value] = core_req[PROTO_CORE_REG_REQ.APP_ID.value]
                        resp_data[PROTO_CORE_REG_RES.APP_PK.value] = veri_key
                        resp_data = ProtoMsgCoreEncMsg.create_msg_data(PROTO_CORE_REG_RES,resp_data)
                    elif core_req["type"]=="Verify":
                        veri_data = self.cryptostore.generate_verification(core_req[PROTO_CORE_VERIFY_REQ.APP_ID.value],core_req[PROTO_CORE_VERIFY_REQ.NONCE.value])
                        resp_data[PROTO_CORE_VERIFY_RES.APP_ID.value] = core_req[PROTO_CORE_VERIFY_REQ.APP_ID.value]
                        resp_data[PROTO_CORE_VERIFY_RES.APP_SIG.value] = veri_data
                        resp_data = ProtoMsgCoreEncMsg.create_msg_data(PROTO_CORE_VERIFY_RES,resp_data)
                    elif core_req["type"]=="Put":
                        put_result = self.cryptostore.put_data(core_req[PROTO_CORE_PUT_REQ.APP_ID.value],B64.decode(core_req[PROTO_CORE_PUT_REQ.DATA.value]))
                        resp_data[PROTO_CORE_PUT_RES.ENC_DATA.value] = put_result
                        resp_data = ProtoMsgCoreEncMsg.create_msg_data(PROTO_CORE_PUT_RES,resp_data)
                    elif core_req["type"]=="Get":
                        get_result = self.cryptostore.get_data(core_req[PROTO_CORE_GET_REQ.APP_ID.value],core_req[PROTO_CORE_GET_REQ.ENC_DATA.value])
                        resp_data[PROTO_CORE_GET_RES.DATA.value] = get_result
                        resp_data = ProtoMsgCoreEncMsg.create_msg_data(PROTO_CORE_GET_RES,resp_data)
                    resp_enc_msg = ProtoMsgCoreEncMsg.parse(resp_data)
                    self.current_protocol.process_outgoing_message(resp_enc_msg)
                    enc_msg = ProtoMsgCoreRespMsg.create_encrypted_json_msg(resp_enc_msg.get_data(),self.current_protocol.derived_key)
                    msg_two = self.current_protocol.prepare_outgoing_msg(self.current_protocol.get_next_message_class().create_msg_data(enc_msg))
                    self.client.send(Message.create_route(self.current_protocol.ephe_address_remote,msg_two.get_data()))
                    #print("Calling close on CD")
                    #self.client.close()
            #self.client.close()
        else:
            logger.debug("Received:%s",msg)
            
    def receive_qr_code(self, data:str):
        self.current_protocol = EnrolmentProtocol(self.identity_store)
        response = self.current_protocol.parse_incoming_msg(data)
        print("ADDRESS:" + self.current_protocol.ephe_address_remote)
        if response is not None:
            self.mode = CD_MODE.ENROL
            self.client.connect()
            self.client.add_listener(self)
            self.client.send(Message.create_init())

    def receive_push(self, data:str):
        self.current_protocol = WSSKeyExchangeProtocol(self.identity_store, None,)
        response = self.current_protocol.parse_incoming_msg(data)
        if response is not None:
            self.mode = CD_MODE.WSS
            self.client.connect()
            self.client.add_listener(self)
            self.client.send(Message.create_init())

class DummyCryptoStore():
    """Dummy Cryto store for the test companion device. Do not use
    outside of testing

    Returns:
        _type_: _description_
    """
    DATA = "data"
    VERI = "verification"
    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"
    def __init__(self, path:str):
        self.path = path
        self.data = {}
        if os.path.exists(self.path):
            with open(self.path, "r") as json_file:
                self.data = json.load(json_file)
        else:
            self.data[DummyCryptoStore.DATA] = {}
            self.data[DummyCryptoStore.VERI]= {}
            self._store()
    
    def _store(self):
        with open(self.path, "w") as json_file:
            json_file.write(json.dumps(self.data))
    
    def create_verification_key(self, app_id:str)->str:
        app = {}
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = CryptoUtils.public_key_to_string(private_key.public_key())
        app[DummyCryptoStore.PRIVATE_KEY] = private_key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8, NoEncryption()).decode("UTF-8")
        app[DummyCryptoStore.PUBLIC_KEY]= public_key
        self.data[DummyCryptoStore.VERI][app_id]=app
        self._store()
        return public_key
    
    def generate_verification(self, app_id:str, nonce:str)->str:
        nonce_bytes = B64.decode(nonce)
        app_data = self.data[DummyCryptoStore.VERI][app_id]
        private_key = serialization.load_pem_private_key(app_data[DummyCryptoStore.PRIVATE_KEY].encode("UTF-8"),None)
        signature = private_key.sign(nonce_bytes,ec.ECDSA(hashes.SHA256()))
        return B64.encode(signature)

    def _get_create_data_key(self, app_id:str)->bytes:
        if app_id in self.data[DummyCryptoStore.DATA]:
            return B64.decode(self.data[DummyCryptoStore.DATA][app_id])
        else:
            key = AESGCM.generate_key(bit_length=256)
            self.data[DummyCryptoStore.DATA][app_id]=B64.encode(key)
            self._store()
            return key
    
    def put_data(self, app_id:str, data:bytes)->dict:
        key = self._get_create_data_key(app_id)
        aesgcm = AESGCM(key)
        iv = os.urandom(12)
        enc_data = {}
        enc_data["cipher_text"]=B64.encode(aesgcm.encrypt(iv, data, None))
        enc_data["iv"]=B64.encode(iv)
        return enc_data
    
    def get_data(self, app_id:str, enc_data:dict)->str:
        key = self._get_create_data_key(app_id)
        aesgcm = AESGCM(key)
        iv = B64.decode(enc_data["iv"])
        cipher_text = B64.decode(enc_data["cipher_text"])
        data = aesgcm.decrypt(iv, cipher_text, None)
        return B64.encode(data)

