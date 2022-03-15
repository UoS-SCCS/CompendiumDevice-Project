#!/usr/bin/env python

from enum import Enum
import sys
from abc import ABC, abstractmethod
from concurrent.futures import thread
import json
from queue import Queue
import socket
from time import sleep
import websockets
from websockets.client import ClientConnection
from websockets.http11 import Request, Response
from websockets.frames import Frame,Opcode
import threading
from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod
import logging
from compendium.storage import KeyRingIdentityStore
from compendium.wss.message import Message,TYPE,INITRESP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey,EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization 
from tkinter import simpledialog
from tkinter.simpledialog import Dialog
import tkinter as tk
import keyring
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler(sys.stdout)
logger.addHandler(streamHandler)
SERVER_ADDRESS="localhost"
SERVER_PORT=8001
WSS_ADDRESS="ws://" + SERVER_ADDRESS + str(SERVER_PORT)

class WssClient():
    def __init__(self,wss_address:str=None) -> None:
        if wss_address is not None:
            self.wss_adr = wss_address
        else:
            self.wss_adr = WSS_ADDRESS
        self.websocket = None

        self.send_queue = Queue()
        self.sock = None
        self.listen_thread = None
        self.frame_buffer = bytearray()
        self._listeners = []
        self.received_queue = Queue()
        self.received_queue_thread = None
        self.send_queue_thread = None
        self.connected=False
        self.shutdown_called=False
        self.close_after_send=False

    def add_listener(self,listener):
        self._listeners.append(listener)

    def remove_listener(self,listener):
        if listener in self._listeners:
            self._listeners.remove(listener)

    def fire_event(self, msg:Message):
        for listener in self._listeners:
            listener.ws_received(msg)

    def send(self,msg:Message):
        self.send_queue.put(msg)

    def set_close_after_send(self):
        self.close_after_send = True

    def process_send_queue(self):
        while True:
            logger.debug("Waiting for message to send")

            msg = self.send_queue.get()
            print("process queue",msg)
            self.connection.send_text(msg.encode_as_bytes())
            logger.debug("Sent message %s",msg)
            self._send_data()
            if self.close_after_send:
                self.close()

    def close(self):
        print("close called")
        if self.connected:
            self.connected = False
            self.connection.send_close(1000)
            self._send_data()
            threading.Thread(target=self._close_socket(),daemon=True).start()
    def _process_frame(self,frame:Frame):
        logger.debug("Received frame: %s",frame)
        if frame.opcode == Opcode.PING:
            self.connection.send_pong(frame.data)
            self._send_data()
        elif frame.opcode == Opcode.TEXT:
            self.frame_buffer.extend(frame.data)
            if frame.fin:
                self.received_queue.put(self.frame_buffer.decode())
                self.frame_buffer.clear()
        elif frame.opcode == Opcode.CLOSE:
            self._close_socket(True)
        else:
            print(frame)

    def _received_queue_processor(self):
        #Process the queue on a thread so it doesn't block sending and receiving
        while True:
            data = self.received_queue.get()
            self.fire_event(Message.parse(data))

    def _process_events(self):
        evts = self.connection.events_received()
        for evt in evts:
            logger.debug("Processing event:%s",evt)
            if isinstance(evt,Response):
                if evt.exception is not None:
                    raise evt.exception
                self.connected=True
                self.send_queue_thread = threading.Thread(target=self.process_send_queue,daemon=True)
                self.send_queue_thread.start()
            elif isinstance(evt,Request):
                print("request received")
            elif isinstance(evt,Frame):
                self._process_frame(evt)
            else:
                raise Exception("Unknown event")


        """
        print("in listen")
        while True:

            try:
                print("waiting to receive")
                message = Message.parse(await self.websocket.recv())
                if(message.type == TYPE.INITRESP):
                    self.EpheWssAddr = message.EpheWssAddr
                    print(self.EpheWssAddr)
                elif(message.type == TYPE.DELIVER):
                    print(message.msg)
                else:
                    print("unknown type")

            except websockets.ConnectionClosedOK:
                self.websocket = None
                break
        """
    def _close_socket(self, immediate=False):
        if not self.shutdown_called:
            self.sock.shutdown(socket.SHUT_WR)
            self.shutdown_called=True
        if immediate:
            self.sock.close()
            return
        sleep(10)
        self.sock.close()


    def _listen(self):
        while True:
            try:
                data = self.sock.recv(4096)
            except OSError:  # socket closed
                data = b""
            if data:
                self.connection.receive_data(data)
            else:
                self.connection.receive_eof()
                self._send_data()
                self.sock.close()
                break
            self._process_events()




    def _send_data(self):
        for data in self.connection.data_to_send():
            if data:
                self.sock.sendall(data)
            else:
                if not self.shutdown_called:
                    self.sock.shutdown(socket.SHUT_WR)
                    self.shutdown_called=True
     

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((SERVER_ADDRESS, SERVER_PORT))
        wsuri = websockets.uri.parse_uri(self.wss_adr)
        self.connection = ClientConnection(wsuri)
        request = self.connection.connect()
        self.connection.send_request(request)
        self._send_data()
        self._process_events()
        self.listen_thread = threading.Thread(target=self._listen)
        self.listen_thread.start()
        self.received_queue_thread = threading.Thread(target=self._received_queue_processor,daemon=True)
        self.received_queue_thread.start()



class WssClientListener(ABC):

    @abstractmethod
    def ws_received(self,msg:Message):
        pass

