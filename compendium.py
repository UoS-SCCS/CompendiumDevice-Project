

from cgi import test
from wss.client import WssClientListener, WssClient, Message, TYPE, INITRESP
from companion.identity import KeyRingIdentityStore
from companion.protocol import EnrolmentProtocol, ProtoMsgConfirmKeyEncMsg, ProtoMsgConfirmKeyMsg,\
    ProtoMsgInitKeyReq,ProtoMsgInitKeyResp, ProtoMsgInitKeyRespEncMsg, ProtoWSSInitKeyReqMsg,\
    ProtoWSSInitKeyRespEncMsg, WSSKeyExchangeProtocol, WSS_KEP_STATE, ProtoMsgCoreEncMsg, ProtoMsgCoreRespMsg, ProtoMsgCoreMsg,\
    PROTO_CORE_GET_REQ,PROTO_CORE_PUT_REQ,PROTO_CORE_REG_REQ,PROTO_CORE_VERIFY_REQ,\
    PROTO_CORE_GET_RES,PROTO_CORE_PUT_RES,PROTO_CORE_REG_RES,PROTO_CORE_VERIFY_RES
import requests
import sys
import logging
import threading
from typing import Union
from enum import Enum
from companion.ui import UI
import json

from wss.message import DELIVER
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler(sys.stdout)
logger.addHandler(streamHandler)

PUSH_SERVER_ADDRESS="http://localhost"
PUSH_SERVER_PORT=5000
PUSH_PATH = "/pushmessage"
class CD_MODE(Enum):
    IDLE=0
    ENROL = 1
    WSS = 2
class Companion(WssClientListener):

    #TODO
    # Generate QRCode
    # Display QRCode
    # Enrolment storage
    # Protocol
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

class PC_MODE(Enum):
    IDLE=0
    ENROL = 1
    WSS = 2
class PC(WssClientListener):
    
    #TODO
    # Generate QRCode
    # Display QRCode
    # Enrolment storage
    # Protocol
    def __init__(self):
        self.identity_store = KeyRingIdentityStore()
        self.ephe_wss_addr_local = None
        self.client = None# WssClient()
        self.current_protocol = None
        self.mode = PC_MODE.IDLE
        self.core_protocol = None
        self.core_protocol_data = None
        self.callback = None
        
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
                UI.show_qr_screen_new_process(msg_one.get_string(),self.qr_callback)
                cd.receive_qr_code(msg_one.get_string())
                pass
            elif self.mode == PC_MODE.WSS:
                #send as push
                
                #self.send_push_notification(self.current_protocol.get_target_public_identity(),msg_one.get_data())
                cd.receive_push(msg_one.get_string())
                pass
        elif msg.get_type() is TYPE.DELIVER:
            logger.debug("Delivered:%s",msg)
            response = self.current_protocol.parse_incoming_msg(msg.get_field_value(DELIVER.MSG.value))
            if response is not None:
                if self.mode == PC_MODE.ENROL:
                    self._process_key_response()
                elif self.mode == PC_MODE.WSS:
                    if self.current_protocol.current_state == WSS_KEP_STATE.INIT_KEY_RESP:
                        self._process_key_response()
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
            
    def _process_key_response(self):
        #PC Prepares confirmation message
        #Create inner signature to be encrypted
        encrypted_confirm_signature = ProtoMsgConfirmKeyEncMsg.parse(ProtoMsgConfirmKeyEncMsg.create_msg_data())
        self.current_protocol.process_outgoing_message(encrypted_confirm_signature)

        #Create encrypted message wrapper
        enc_msg = ProtoMsgConfirmKeyMsg.create_encrypted_json_msg(encrypted_confirm_signature.get_data(),self.current_protocol.derived_key)
        confirm_message = self.current_protocol.prepare_outgoing_msg(ProtoMsgConfirmKeyMsg.create_msg_data(enc_msg))
        self.client.send(Message.create_route(self.current_protocol.ephe_address_remote,confirm_message.get_data()))

    def _process_core_request(self):
        #ProtoMsgCoreEncMsg, ProtoMsgCoreRespMsg, ProtoMsgCoreMsg
        core_msg = ProtoMsgCoreEncMsg.parse(ProtoMsgCoreEncMsg.create_msg_data(self.core_protocol,self.core_protocol_data))
        self.current_protocol.process_outgoing_message(core_msg)

        #Create encrypted message wrapper
        wrapper_msg = ProtoMsgCoreMsg.create_encrypted_json_msg(core_msg.get_data(),self.current_protocol.derived_key)
        confirm_message = self.current_protocol.prepare_outgoing_msg(ProtoMsgCoreMsg.create_msg_data(wrapper_msg))
        self.client.send(Message.create_route(self.current_protocol.ephe_address_remote,confirm_message.get_data()))


    def start_enrolment(self):
        self.client = WssClient()
        self.current_protocol = EnrolmentProtocol(self.identity_store)
        self.mode = PC_MODE.ENROL
        self.client.connect()
        self.client.add_listener(self)
        self.client.send(Message.create_init())
    
    def start_wss(self, key_id:str, core_protocol:Union[PROTO_CORE_GET_REQ,PROTO_CORE_PUT_REQ,PROTO_CORE_REG_REQ,PROTO_CORE_VERIFY_REQ], core_protocol_data,callback):
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
        
import os

from companion.utils import CryptoUtils, B64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey,EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
class DummyCryptoStore():
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



test_nonce = None
def verify_callback(data):
    global test_nonce
    global test_key
    print(test_nonce)
    print("VErify Callback")
    public_key = CryptoUtils.load_public_key_from_string(test_key)
    print(public_key.verify(B64.decode(data[PROTO_CORE_VERIFY_RES.APP_SIG.value]), test_nonce, ec.ECDSA(hashes.SHA256())))
    print("Key Verified")
    print("callback",data)

test_key = None
def reg_callback(data):
    global test_key
    test_key = data[PROTO_CORE_REG_RES.APP_PK.value]
    print(test_key)
    global cd
    global pc
    cd = Companion()
    pc = PC()
    test_verify(pc)

enc_data = None
def put_callback(data):
    global enc_data
    enc_data = data[PROTO_CORE_PUT_RES.ENC_DATA.value]
    print("PUT callback")
    print(enc_data)
    global cd
    global pc
    cd = Companion()
    pc = PC()
    test_get(pc)

def get_callback(data):
    data = B64.decode(data[PROTO_CORE_GET_RES.DATA.value]).decode("UTF-8")
    print(data)

def test_reg(pc):
    key = pc.get_key_id_from_name("CD")
    data = {}
    data[PROTO_CORE_REG_REQ.APP_ID.value]="MyApp"
    data[PROTO_CORE_REG_REQ.DESC.value]="Let's go"
    data[PROTO_CORE_REG_REQ.ID_CD.value]="CD"
    pc.start_wss(key,PROTO_CORE_REG_REQ,data,reg_callback)

def test_verify(pc):
    data = {}
    global test_nonce
    test_nonce=os.urandom(12)
    print(test_nonce)
    data[PROTO_CORE_REG_REQ.APP_ID.value]="MyApp"
    data[PROTO_CORE_VERIFY_REQ.DESC.value]="Let's go"
    data[PROTO_CORE_VERIFY_REQ.ID_CD.value]="CD"
    data[PROTO_CORE_VERIFY_REQ.CODE.value]="1234"
    data[PROTO_CORE_VERIFY_REQ.NONCE.value]=B64.encode(test_nonce)
    print("about to call verify")
    pc.start_wss(key,PROTO_CORE_VERIFY_REQ,data,verify_callback)

def test_put(pc):
    key = pc.get_key_id_from_name("CD")
    data = {}
    
    data[PROTO_CORE_PUT_REQ.APP_ID.value]="MyApp"
    data[PROTO_CORE_PUT_REQ.DESC.value]="Let's go"
    data[PROTO_CORE_PUT_REQ.ID_CD.value]=key
    data[PROTO_CORE_PUT_REQ.CODE.value]="1234"
    data[PROTO_CORE_PUT_REQ.DATA.value]=B64.encode("Hello mr brightside".encode("UTF-8"))
    pc.start_wss(key,PROTO_CORE_PUT_REQ,data,put_callback)

def test_get(pc):
    global enc_data
    key = pc.get_key_id_from_name("CD")
    data = {}
    data[PROTO_CORE_GET_REQ.APP_ID.value]="MyApp"
    data[PROTO_CORE_GET_REQ.DESC.value]="Let's go"
    data[PROTO_CORE_GET_REQ.ID_CD.value]=key
    data[PROTO_CORE_GET_REQ.CODE.value]="1234"
    data[PROTO_CORE_GET_REQ.ENC_DATA.value]=enc_data
    pc.start_wss(key,PROTO_CORE_GET_REQ,data,get_callback)
pc = None
cd = None
if __name__ == "__main__":

    pc = PC()
    cd = Companion()
    
    #print(pc.get_key_ids())
    #print(pc.get_key_names())
    #pc.start_enrolment()
    key = pc.get_key_id_from_name("CD")
    #test_reg(pc)
    test_put(pc)
    input("Press Enter to continue...")
    #pc
    #print(key)
    #data = {}
    #data[PROTO_CORE_REG_REQ.APP_ID.value]="MyApp"
    #data[PROTO_CORE_REG_REQ.DESC.value]="Let's go"
    #data[PROTO_CORE_REG_REQ.ID_CD.value]="CD"
    #pc.start_wss(key,PROTO_CORE_REG_REQ,data,callback)
    

    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH/24HoN/UoXqpAzbPc1616CIP/SPFc07jXmIGM9Dhnu40mAkpxeG3E5SWG6PQWPFBdLyNELp+n1T74W5Ov/MKw=="
    
    #data = {}
    #test_nonce=os.urandom(12)
    #data[PROTO_CORE_REG_REQ.APP_ID.value]="MyApp"
    #data[PROTO_CORE_VERIFY_REQ.DESC.value]="Let's go"
    #data[PROTO_CORE_VERIFY_REQ.ID_CD.value]="CD"
    #data[PROTO_CORE_VERIFY_REQ.CODE.value]="1234"
    #data[PROTO_CORE_VERIFY_REQ.NONCE.value]=B64.encode(test_nonce)
    
    #pc.start_wss(key,PROTO_CORE_VERIFY_REQ,data,verify_callback)

    #data[PROTO_CORE_REG_REQ.APP_ID.value]="MyApp"
    #data[PROTO_CORE_REG_REQ.DESC.value]="Let's go"
    #data[PROTO_CORE_REG_REQ.ID_CD.value]="CD"
    #pc.start_wss(key,PROTO_CORE_REG_REQ,data,callback)
    
    #test_enrolment()
    #test_wss()
    
    
    #print(kep.parse_next_msg())
    if(True):
        exit()

