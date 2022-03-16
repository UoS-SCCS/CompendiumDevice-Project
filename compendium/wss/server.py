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
import asyncio
import json

import os
import ssl
import uuid

import websockets

from message import TYPE, Message

#TODO add logging 

#Connection indexes CONNS indexs by Address, CONNSIDX by web socket
#We need both to be able to react to events coming from a web socket
#for example a close request which won't have an address with it
CONNS = {}
CONNSIDX = {}

#TLS Certificate locations
SSLPATHCERT="/etc/letsencrypt/live/compendium.dev.castellate.com/fullchain.pem"
SSLKEY="/etc/letsencrypt/live/compendium.dev.castellate.com/privkey.pem"

"""
Provides a Web Socket Server for the Compendium Protocol.

Note, this server does not attempt to maintain state between
restarts. i.e. all existing connections will be lost if the 
server restarts. 
"""
async def handler(websocket):
    while True:
        try:
            message = Message.parse(await websocket.recv())
            if(message.type == TYPE.INIT):
                adr = uuid.uuid4()
                CONNS[adr.hex] = websocket
                CONNSIDX[websocket] = adr.hex
                await websocket.send(Message.create_init_response(adr.hex).encode())
            elif(message.type == TYPE.ROUTE):
                if(message.EpheWssAddr in CONNS):
                    await CONNS[message.EpheWssAddr].send(Message.create_deliver(message).encode())
                else:
                    await websocket.send(Message.create_error(404,"Socket address not found").encode())
            else:
                print("unknown type")

        except websockets.ConnectionClosedOK:
            del CONNS[CONNSIDX[websocket]]
            del CONNSIDX[websocket]
            break


async def main():
    """Main function that establishes a the web socket server and
    starts the asyncio call. This handles both secure and unsecure
    connections, but the latter shouldn't be used and is only still
    present as it was needed during development.
    """
    if os.path.exists(SSLPATHCERT):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(SSLPATHCERT, keyfile=SSLKEY)    
        async with websockets.serve(handler, "", 8001, ssl=ssl_context):
            await asyncio.Future()  # run forever
    else:
        async with websockets.serve(handler, "", 8001):
            await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
