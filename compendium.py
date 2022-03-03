

from cgi import test
from wss.client import WssClientListener, WssClient, Message, TYPE, INITRESP
from companion.identity import KeyRingIdentityStore
from companion.protocol import EnrolmentProtocol, ProtoMsgConfirmKeyEncMsg, ProtoMsgConfirmKeyMsg,ProtoMsgInitKeyReq,ProtoMsgInitKeyResp, ProtoMsgInitKeyRespEncMsg, ProtoWSSInitKeyReqMsg, ProtoWSSInitKeyRespEncMsg, WSSKeyExchangeProtocol
import sys
import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler(sys.stdout)
logger.addHandler(streamHandler)

class Companion(WssClientListener):

    #TODO
    # Generate QRCode
    # Display QRCode
    # Enrolment storage
    # Protocol
    def __init__(self):
        self.ephe_wss_addr_local = None
        self.client = WssClient()
        self.client.connect()
        self.client.add_listener(self)
        self.client.send(Message.create_init())

    def ws_received(self, msg: Message):
        if msg.get_type() is TYPE.INITRESP:
            self.ephe_wss_addr_local=msg[INITRESP.ADR.value]
            logger.debug("Set client address:%s",self.ephe_wss_addr_local)
        elif msg.get_type() is TYPE.DELIVER:
            logger.debug("Delivered:%s",msg)
            self.client.close()
        else:
            logger.debug("Received:%s",msg)

    def establish_secure_connection(self, remote_adr:str):
        proto1 = {"test":"testmessage"}
        self.client.send(Message.create_route(remote_adr,proto1))


class PC():
    def __init__(self):
        self.identity = KeyRingIdentityStore()
        


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


if __name__ == "__main__":

    pc = PC()
    #test_enrolment()
    test_wss()
    
    
    #print(kep.parse_next_msg())
    if(True):
        exit()
