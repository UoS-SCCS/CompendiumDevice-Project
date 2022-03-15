#!/usr/bin/env python
import os
import asyncio
import uuid
import ssl
import websockets
import json
from message import Message,TYPE

CONNS = {}
CONNSIDX = {}
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

SSLPATHCERT="/etc/letsencrypt/live/compendium.dev.castellate.com/fullchain.pem"
SSLKEY="/etc/letsencrypt/live/compendium.dev.castellate.com/privkey.pem"

async def main():
    
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