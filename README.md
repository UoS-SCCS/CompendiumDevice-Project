# Companion_WSS
Websocket Server for Companion Authentication Project

Provides a simple Websocket server (WSS) that acts like a router to allow a PC and companion device (CD) to communicate between eachother without having to be able to listen to external ports. Each device requests an address from the WSS. The WSS randomly generates an ephemeral address and returns it to the requesting device. Any messages subsequently sent to that address will be delivered to that device.
