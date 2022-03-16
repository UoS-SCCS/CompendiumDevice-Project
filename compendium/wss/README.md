# Provides a Web Socket Client and Server
Provides both an implementation for a web socket client and server, both of which use the [Python WebSocket library](https://websockets.readthedocs.io/en/stable/#). Ideally the server will be refactored out from this library since it does not require the bulk of the code or dependencies that the library does. It is currently included here because it does need to share the message.py. Longer term messages.py should be in a separate repositories with the server in its own repository as well. Both the library and server would then include the messages as git submodule. 

## Client
The client provides an implementation for the Compendium Library to use in order to establish a connection to the web socket server. The implementation of the client is quite involved because we cannot use the asyncio implementation and must instead use the SansIO option and implement considerably more of the networking and message handling, resulting in increased thread handling. As such, this still needs further refinement to address a possible race condition during closure of the web socket. Details are provided in the commented code. 

## Server
The server provides an implementation of the Web Socket Server in the Compendium protocol. In essence it acts as a relay between PCs and Companion Devices, each of which establish their own ephemeral connections to the Web Socket Server. They share their ephemeral addresses with each other and rely on the Web Socket Server to relay messages between them.

The implementation of the server is far simpler than the client. This is because the server is intended to run independently of any other application, so can make use of the asyncio functionality.

Note: due to the ephemeral nature of the connections the server does not attempt to maintain state between restarts. Addresses are held only in memory and not written to disk and thus are lost during a server restart. This is likely OK because not only should a restart be a rare occurrence, but were it to happen any clients currently connected would likely have to retry the protocol from scratch in any case due to possibly lost messages. 

## Message Structure
All messages should have a `type` field which is used to determine the appropriate message type. Only messages that validate against a message type will be accepted and processed, thus all fields are required.

### Types of messages
* INIT - Requests from a client for a new ephemeral address
* INITRESP - Response from the server containing that address
* ROUTE - Client request to route a message to a target
* DELIVER - Server message to a client containing a message for them
* ERR - Error message

### INIT
```json
{
    "type":"INIT"
}
```

### INITRESP
```json
{
    "type":"INITRESP",
    "EpheWssAddr":"hex encoded random ephemeral address to use"
}
```

### ROUTE
```json
{
    "type":"ROUTE",
    "EpheWssAddr":"hex encoded address of target",
    "msg":{
            //JSON Object containing arbitrary message
          }
}
```

### DELIVER
```json
{
    "type":"DELIVER",
    "msg":{
            //JSON Object containing arbitrary message
          }
}
```

### ERROR
```json
{
    "type":"ERROR",
    "errCode":0, //int error code
    "errMsg":"", //String error message
}


