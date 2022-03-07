

from cgi import test
from wss.client import WssClientListener, WssClient, Message, TYPE, INITRESP
from companion.identity import KeyRingIdentityStore
from companion.protocol import EnrolmentProtocol, ProtoMsgConfirmKeyEncMsg, ProtoMsgConfirmKeyMsg,ProtoMsgInitKeyReq,ProtoMsgInitKeyResp, ProtoMsgInitKeyRespEncMsg, ProtoWSSInitKeyReqMsg, ProtoWSSInitKeyRespEncMsg, WSSKeyExchangeProtocol
import requests
import sys
import logging
import threading
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
                print("Protocol Completed")
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
        self.current_protocol = WSSKeyExchangeProtocol(self.identity_store)
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
        self.client = WssClient()
        self.current_protocol = None
        self.mode = PC_MODE.IDLE
        
    def qr_callback(self,res):
        print("qrcallback:" + res)    

    def get_key_from_name(self, name:str)->str:
        return self.identity_store.get_public_identity_str_from_name(name)
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
                #cd.receive_qr_code(msg_one.get_string())
                pass
            elif self.mode == PC_MODE.WSS:
                #send as push
                
                self.send_push_notification(self.current_protocol.get_target_id(),msg_one.get_data())
                #cd.receive_push(msg_one.get_string())
                pass
        elif msg.get_type() is TYPE.DELIVER:
            logger.debug("Delivered:%s",msg)
            response = self.current_protocol.parse_incoming_msg(msg.get_field_value(DELIVER.MSG.value))
            if response is not None:
                #Valid message received
                
                #PC Prepares confirmation message
                #Create inner signature to be encrypted
                encrypted_confirm_signature = ProtoMsgConfirmKeyEncMsg.parse(ProtoMsgConfirmKeyEncMsg.create_msg_data())
                self.current_protocol.process_outgoing_message(encrypted_confirm_signature)

                #Create encrypted message wrapper
                enc_msg = ProtoMsgConfirmKeyMsg.create_encrypted_json_msg(encrypted_confirm_signature.get_data(),self.current_protocol.derived_key)
                confirm_message = self.current_protocol.prepare_outgoing_msg(ProtoMsgConfirmKeyMsg.create_msg_data(enc_msg))
                self.client.send(Message.create_route(self.current_protocol.ephe_address_remote,confirm_message.get_data()))
            #self.client.close()
        else:
            logger.debug("Received:%s",msg)
            
                

    def start_enrolment(self):
        self.current_protocol = EnrolmentProtocol(self.identity_store)
        self.mode = PC_MODE.ENROL
        self.client.connect()
        self.client.add_listener(self)
        self.client.send(Message.create_init())
    
    def start_wss(self, key_id:str):
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
        


def test_enrolment():
    kepPC = EnrolmentProtocol(KeyRingIdentityStore())
    kepCD = EnrolmentProtocol(KeyRingIdentityStore("Compendium2"))
    
    #PC Creates keys and QRCode content
    msgOne = kepPC.prepare_outgoing_msg(ProtoMsgInitKeyReq.create_msg_data("testAdr"))

    #CD Scans QRCode
    kepCD.parse_incoming_msg(msgOne.get_string())

    #CD Prepares Encrypted Inner Message Response
    resp_enc_msg = ProtoMsgInitKeyRespEncMsg.parse(ProtoMsgInitKeyRespEncMsg.create_msg_data("testCdAdr"))
    kepCD.process_outgoing_message(resp_enc_msg)

    #CD Prepares outer message
    enc_msg = ProtoMsgInitKeyResp.create_encrypted_json_msg(resp_enc_msg.get_data(),kepCD.derived_key)
    msg_two = kepCD.prepare_outgoing_msg(ProtoMsgInitKeyResp.create_msg_data(enc_msg))

    #CD would send via WSS and PC would receive

    #PC Receives response via WSS
    received_msg_two = kepPC.parse_incoming_msg(msg_two.get_string())

    #PC Prepares confirmation message
    #Create inner signature to be encrypted
    encrypted_confirm_signature = ProtoMsgConfirmKeyEncMsg.parse(ProtoMsgConfirmKeyEncMsg.create_msg_data())
    kepPC.process_outgoing_message(encrypted_confirm_signature)

    #Create encrypted message wrapper
    enc_msg = ProtoMsgConfirmKeyMsg.create_encrypted_json_msg(encrypted_confirm_signature.get_data(),kepCD.derived_key)
    confirm_message = kepPC.prepare_outgoing_msg(ProtoMsgConfirmKeyMsg.create_msg_data(enc_msg))
    
    #PC Sends via WSS CD receives from WSS
    kepCD.parse_incoming_msg(confirm_message.get_string())
    
    print("Protocol Finished")
    print(kepCD.derived_key)
    print(kepPC.derived_key)

    print(kepCD.current_state)
    print(kepPC.current_state)

def test_wss():
    
    kepPC = WSSKeyExchangeProtocol(KeyRingIdentityStore())
    kepCD = WSSKeyExchangeProtocol(KeyRingIdentityStore("Compendium2"))
    
    #PC Creates keys and prepares msg for PushServer
    msgOne = kepPC.prepare_outgoing_msg(ProtoWSSInitKeyReqMsg.create_msg_data("testAdr"))

    #CD Receives Push
    kepCD.parse_incoming_msg(msgOne.get_string())

    #CD Prepares Encrypted Inner Message Response
    resp_enc_msg = ProtoWSSInitKeyRespEncMsg.parse(ProtoWSSInitKeyRespEncMsg.create_msg_data("testCdAdr"))
    kepCD.process_outgoing_message(resp_enc_msg)

    #CD Prepares outer message
    enc_msg = ProtoMsgInitKeyResp.create_encrypted_json_msg(resp_enc_msg.get_data(),kepCD.derived_key)
    msg_two = kepCD.prepare_outgoing_msg(ProtoMsgInitKeyResp.create_msg_data(enc_msg))

    #CD would send via WSS and PC would receive

    #PC Receives response via WSS
    received_msg_two = kepPC.parse_incoming_msg(msg_two.get_string())

    #PC Prepares confirmation message
    #Create inner signature to be encrypted
    encrypted_confirm_signature = ProtoMsgConfirmKeyEncMsg.parse(ProtoMsgConfirmKeyEncMsg.create_msg_data())
    kepPC.process_outgoing_message(encrypted_confirm_signature)

    #Create encrypted message wrapper
    enc_msg = ProtoMsgConfirmKeyMsg.create_encrypted_json_msg(encrypted_confirm_signature.get_data(),kepCD.derived_key)
    confirm_message = kepPC.prepare_outgoing_msg(ProtoMsgConfirmKeyMsg.create_msg_data(enc_msg))
    
    #PC Sends via WSS CD receives from WSS
    kepCD.parse_incoming_msg(confirm_message.get_string())
    
    print("Protocol Finished")
    print(kepCD.derived_key)
    print(kepPC.derived_key)

    print(kepCD.current_state)
    print(kepPC.current_state)

pc = None
cd = None
if __name__ == "__main__":

    pc = PC()
    #cd = Companion()
    #print(pc.get_key_ids())
    #print(pc.get_key_names())
    #pc.start_enrolment()
    key = pc.get_key_from_name("Android SDK built for x86")
    print(key)
    pc.start_wss(key)
    
    #test_enrolment()
    #test_wss()
    
    
    #print(kep.parse_next_msg())
    if(True):
        exit()
