#!/usr/bin/env python

import asyncio
import uuid
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

async def main():
    async with websockets.serve(handler, "", 8001):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())