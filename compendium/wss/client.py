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
import logging
import socket
import ssl
import sys
import threading
import tkinter as tk
from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod
from concurrent.futures import thread
from enum import Enum
from queue import Empty, Queue
from time import sleep
from tkinter import simpledialog
from tkinter.simpledialog import Dialog

import keyring
import websockets
from compendium.storage import KeyRingIdentityStore
from compendium.wss.message import INITRESP, TYPE, Message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          PublicFormat)
from websockets.client import ClientConnection
from websockets.frames import Frame, Opcode
from websockets.http11 import Request, Response

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler(sys.stdout)
logger.addHandler(streamHandler)

#Development server - not guaranteed to remain active
SERVER_ADDRESS = "compendium.dev.castellate.com"
SERVER_PORT = 8001
WSS_ADDRESS = "wss://" + SERVER_ADDRESS + ":" + str(SERVER_PORT)

class WssClientListener(ABC):
    """Listener interface to receive received messages from
    the web socket server

    """
    @abstractmethod
    def ws_received(self, msg: Message):
        """Abstract method that defines the ws_received event

        This will be called when a message is received and will
        send a Message object containing the received message
        to the listener.

        Args:
            msg (Message): Received message wrapped in a Message object
        """
        pass

class WssClient():
    """Provides a SansIO implementation of Python websockets. We have
    to use a SansIO approach because asyncio conflicts with out
    main thread users and since this is going to be called as 
    a library it must not impact on the main thread.
    """
    def __init__(self, wss_address: str = None) -> None:
        """Create a new Web Socket Client that will connect to the 
        provided address. However, note, this does not connect
        during construction a separate call to connect must be made
        to actually connect to the address.

        If no wss_address is provided the hardcoded development server
        will be used.

        Args:
            wss_address (str, optional): Web Socket Server address. Defaults to None.
        """
        if wss_address is not None:
            self.wss_adr = wss_address
        else:
            self.wss_adr = WSS_ADDRESS
        self.websocket = None

        #Create a send queue so the send operatin can occur on a different thread
        self.send_queue = Queue()
        self.send_queue_thread = None
        
        #Same for the received queue
        self.received_queue = Queue()
        self.received_queue_thread = None
        
        self.sock = None
        self.listen_thread = None
        self.frame_buffer = bytearray()
        self._listeners = []

        #TODO These are all used for connection management which remains
        #suboptimal with a race condition still occurring. This will need
        #further refactoring to address that, a suggested approach is 
        #given below, but expect these variables to change or be removed
        #after that refactoring. 

        #Tracks if this is connected or not
        self.connected = False
        #Tracks if shutdown has been called
        self.shutdown_called = False
        #Requests a close after the message is sent
        self.close_after_send = False

    def add_listener(self, listener:WssClientListener):
        """Adds a listener for received messages

        Args:
            listener (WssClientListener): listener that implements the WssClientListener interface
        """
        self._listeners.append(listener)

    def remove_listener(self, listener:WssClientListener):
        """Removes the specified listener

        Args:
            listener (WssClientListener): Listener to remove
        """
        if listener in self._listeners:
            self._listeners.remove(listener)

    def fire_event(self, msg: Message):
        """Notify the listeners of the received message

        TODO consider moving this to a separate thread so that
        additional processing by the listener doesn't delay sending
        to other listeners. Not an issue in the current proof of 
        concept as we have only one listener

        Args:
            msg (Message): received message
        """
        for listener in self._listeners:
            listener.ws_received(msg)

    def send(self, msg: Message):
        """Adds the message to the send queue so that it can
        be sent as soon as the sender thread has capacity to do
        so. In theory this could be almost instantaneous, but depends
        on thread scheduling. 

        Args:
            msg (Message): message to send
        """
        self.send_queue.put(msg)

    def set_close_after_send(self):
        """Sets the close_after_send variable to True which should
        trigger the client to close after sending the next message.
        This can be called just before sending the final message.
        """
        self.close_after_send = True

    def process_send_queue(self):
        """Function to process the send queue. This should be run in 
        its own thread as it blocks on the get of the send queue and 
        runs an infinite loop waiting for messages to send.

        TODO refactor to handle closure as well. Currently there is a
        race condition caused by this thread getting a message from the
        queue but not finishing sending it before another thread closes
        the underlying web socket client.
        """
        while True:
            logger.debug("Waiting for message to send")

            msg = self.send_queue.get()
            if msg == "#CLOSE":
                if self.connected:
                    self.connected = False
                    self.connection.send_close(1000)
                    self._send_data()
                    threading.Thread(target=self._close_socket(), daemon=True).start()
            else:
                self.connection.send_text(msg.encode_as_bytes())
                logger.debug("Sent message")
                self._send_data()
                if self.close_after_send:
                    logger.debug("Close after send set, will call close")
                    self.close()

    def close(self):
        """Closes the underlying web socket client.
        
        TODO this needs refactoring there is still a race condition
        between the close call and the process call. This should be
        changed so close is in fact called from process_send_queue
        using a carefully craft close message added to the send_queue.
        That way we guarantee that the close is called after the last
        send
        """ 
        logger.debug("Close called")
        if self.connected:
            self.send_queue.put("#CLOSE")
            

    def _process_frame(self, frame: Frame):
        """Process a received web socket frame. Note, this has to handle
        all web socket frames, not just the ones we are interested in, i.e. text
        frames. As such, we must implement the PING and CLOSE frame
        handling as well.

        Args:
            frame (Frame): received frame
        """
        logger.debug("Received frame: %s", frame)
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
            logger.error("Unknown frame type: %s", frame)

    def _received_queue_processor(self):
        """Processes the received message on separate thread so that
        we don't block receiving, and, for example, miss and PING
        message.
        """
        # Process the queue on a thread so it doesn't block sending and receiving
        while True:
            data = self.received_queue.get()
            self.fire_event(Message.parse(data))

    def _process_events(self):
        """
        Process underlying events from the connection.
        Note we only implement client events, and as
        such ignore request events since we are not acting
        as a server
        """
        evts = self.connection.events_received()
        for evt in evts:
            logger.debug("Processing event:%s", evt)
            if isinstance(evt, Response):
                if evt.exception is not None:
                    raise evt.exception
                self.connected = True
                self.send_queue_thread = threading.Thread(
                    target=self.process_send_queue, daemon=True)
                self.send_queue_thread.start()
            elif isinstance(evt, Request):
                logger.error("Received a request event to a client")                
            elif isinstance(evt, Frame):
                self._process_frame(evt)
            else:
                raise Exception("Unknown event")

    def _close_socket(self, immediate=False):
        """Internal close socket logic. If immediate is set to 
        True it will close the socket immediately instead of 
        waiting 10 seconds for any final shutdown messages to
        be sent. Note, this call will wait for 10 seconds, so
        caution should be used as to where this is called from
        to avoid unintentional application hangs.

        Args:
            immediate (bool, optional): True to shut the socket immediately. Defaults to False.
        """
        if not self.shutdown_called:
            self.sock.shutdown(socket.SHUT_WR)
            self.shutdown_called = True
        if immediate:
            self.sock.close()
            return
        sleep(10)
        self.sock.close()

    def _listen(self):
        """Listen function that should be called on a separate thread
        to listen to the underlying socket. Data is read of the socket
        and passed to the underlying web socket library to reconstruct
        into appropriate frames.
        """
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
        """Sends the actual data on the socket by reading from the
        web socket client buffer and writing to the underlyng socket.
        """
        for data in self.connection.data_to_send():
            if data:
                self.sock.sendall(data)
            else:
                if not self.shutdown_called:
                    self.sock.shutdown(socket.SHUT_WR)
                    self.shutdown_called = True

    def connect(self):
        """Call to connect to the web socket server. This will connect
        to the web socket address provided during instantiation.

        Requires a secure web socket server to connect to
        """
        logger.debug("Connect called")
        context = ssl.create_default_context()
        self.sock = socket.create_connection((SERVER_ADDRESS, SERVER_PORT))
        self.sock = context.wrap_socket(
            self.sock, server_hostname=SERVER_ADDRESS)

        logger.debug("Secure socket established")
        wsuri = websockets.uri.parse_uri(self.wss_adr)
        self.connection = ClientConnection(wsuri)
        request = self.connection.connect()
        logger.debug("Web socket request sent")
        self.connection.send_request(request)
        self._send_data()
        self._process_events()
        logger.debug("Creating listen and receive threads")
        #TODO check that these threads are correctly destroyed following a close call
        self.listen_thread = threading.Thread(target=self._listen)
        self.listen_thread.start()
        self.received_queue_thread = threading.Thread(
            target=self._received_queue_processor, daemon=True)
        self.received_queue_thread.start()


