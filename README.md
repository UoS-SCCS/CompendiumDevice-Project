# Compendium Project
This repository is part of the Compendium Project that built a proof of concept for leveraging the biometric security capabilities found on mobile devices for desktop/laptop security. The project developed a number of protocols and applications to provide a general purpose framework for storing and accessing biometrically protected credentials on a mobile device. A security analysis of the protocols has been undertaken using Tamarin.

The project developed both the backend services and an Android demonstrator app. The framework has been integrated with our previously developed virtual authenticator to show the use of biometrics for secure storage of data on the PC and for performing a biometrically protected user verification.

The list of relevant repositories is as follows:
* [Compendium Library](https://github.com/UoS-SCCS/Compendium-Library) - Provides the Python library to be included by the PC based app that wishes to use the protocol
* [Compendium App](https://github.com/UoS-SCCS/Compendium-Android) - The Android app that provides the companion device functionality
* [Compendium PushServer](https://github.com/UoS-SCCS/Compendium-PushServer) - Provides back-end functionality for the communications protocol
* [Virtual Authenticator with Compendium](https://github.com/UoS-SCCS/VirtualAuthenticatorWithCompendium-) - An extension of development Virtual Authenticator which includes Compendium for secure storage of config data and user verification
* [Security Models](https://github.com/UoS-SCCS/Companion-Device---Tamarin-Models-) - Tamarin security models of the protocol

# Compendium Library
Provides the core PC library for the Compendium project. Currently it is implemented in Python, but a longer term goal is to implement across multiple languages. This library is intended to be included by other applications that wish to make use of the Compendium protocol and the biometric security offered. It has been written to not interfere with existing main thread functionality, for example, QT, so should be safe for inclusion in such applications. It does, however, have some UI components, most notably the display of an enrolment QRCode. This is currently performed in a dedicated child process distinct from the calling process to allow for a separate main thread to be established. Longer term the QRCode could be returned to the client to allow it to display it as it so chooses.

Currently this repository also house the Web Socket Server for the project, although that will eventually be refactored into its own dedicated repository. For more information on the Web Socket Server and Client implementations, including message structures see [Web Socket Readme](./wss/README.md)

A usage guide for the library is provided first, followed by breakdown of the various components of the library, the latter being of interest for further development.

## Demo
The following provides a short video showing Compendium in operation with our Virtual Authenticator. The video from the device is recorded on a Pixel 6 which hides the UI when performing a biometric authentication. To show what that UI looks like, please see below for an example that was recorded on an Android Emulator.


https://user-images.githubusercontent.com/19400530/167898809-b00ee2dd-c7ab-4374-8bc9-e7b395b18848.mp4



[Demo Video Direct Link](https://youtu.be/-c52wLQ_pIg)


### UI - Recorded on Android Emulator
This following shows, enrolment followed by registration for User Verification, and a Verification challenge.

https://user-images.githubusercontent.com/19400530/167899814-c4115b76-9f3a-4309-9cb1-c92e56bd3cb2.mp4

[UI Video Direct Link](https://youtu.be/cp48pj2cXMY)



## Usage
The entry point for usage of the library is the Compendium class in `compendium.client`. The constructor for the Compendium class takes one optional argument `identity_store` of type IdentityStore. By default this will be the system wide `KeyRingIdentityStore` shared by all applications. If an application wishes to have sole control over the identity store, and therefore its own dedicated identity keys, it should provide an instance of its own IdentityStore implementation, see [Data Storage](#DataStorage) below.

This class provides the following functions:

* `get_enrolled_devices`
  * Provides a list of enrolled devices.
* `enrol_new_device`
  * Starts enrolment for a new device.
* `register_user_verification`
  * Registers the specified APPID for a user verification key.
* `perform_user_verification`
  * Performs a user verification request by challenging the Companion Device to sign a random challenge with the corresponding private key to the public key provided during registration for user verification.
* `put_data`
  * Requests the Companion Device to encrypt the specified data and return the encrypted blob. It is the job of the caller to store the returned encrypted blob so it can later be passed to `get_data` to decrypt it when needed.
* `get_data`
  * Requests the Companion Device decrypts the specified previously encrypted blob. Will receive the decrypted plaintext in return. 
* `verify_signature`
  * Utility method for verifying signatures.
* `reset`
  * Resets the Compendium protocol ready to run another request, this must be called before running a second request otherwise the request will be rejected as the Compendium client only permits one protocol to be active at a time.

Each of the messages, with the exception of `get_enrolled_devices`, `verify_signature` and `reset` operate on the basis of callbacks. This is because they run on a separate thread to the caller. The caller must provide a suitable callback function of the form `(data, error=None)` to receive callbacks. The data from the request will be contained within the data object, which may be a string, or may be a dictionary. If error is not None it indicates the protocol failed. 

For an example implementation see `demoapp.py` which contains a simple command line UI to enrol a device and test the various functions. 

### <a id="DataStorage"></a>Data Storage
#### IdentityStore
The identity store provides a storage interface for the identity keys of the PC (the asymmetric key pair used to authenticate the PC both during Diffie-Hellman key exchanges and in the Compendium protocol) and the public identity keys received from Companion Devices.  It is abstractly defined in the `IdentityStore` class. Importantly, it does not define how the underlying values should be stored. 

#### PublicIdentityStore
Provides a storage interface for received public identity keys from enrolled Companion Devices. It is abstractly defined in the `PublicIdentityStore` class. Separating this from the `IdentityStore` can be useful since these values are inherently public so don't need such careful storage.

#### KeyRingIdentityStore
Provides an implementation of the `IdentityStore`. Combines storage of private key data in the system key ring, whilst using a `JSONPublicKeyIdentityStore` which is an implementation of the `PublicIdentityStore` for storing public identities received from Companion Devices. The `JSONPublicKeyIdentityStore` stores received public keys and their respective name and ID maps in a JSON file. In the case of the `KeyRingIdentityStore` that JSON file is stored in the users home directory `~/.compendium/data/PROFILE ID/public_ids_.json`, whereby `PROFILE_ID` is a GUID generated at random when first created and stored in the system key ring. All values in the system key ring are prefixed with "Compendium".

## Protocol Implementation
`protocol.py` contains the protocol implementation. The concept behind the implementation was to provide as flexible a core protocol handler as possible, with as much code generalised into inherited classes. As such, a series of ProtocolMessage classes are implemented to represent different types and functionality of messages, for example, whether a message is signed or encrypted. They then contain the necessary methods for processing such a message either as an incoming or outgoing message. 

For example, the `SignatureMessage` is a subclass of ProtocolMessage and provides functionality to sign outgoing messages and verify the signature of incoming messages. The specific messages for use in the protocol are then relatively lightweight, defining their functionality through subclassing. For example, the `ProtoMsgInitKeyReq` subclasses the `SignatureMessage` and `STSDHECKeyExchangeMessage` message classes as it both signs and verifies message content and is part of the STS Diffie-Hellman key exchange. 

The following abstract message types have been implemented:

* `ProtocolMessage` - core functionality including validation and message parsing
  * `SignatureMessage` - signs and verifies
  * `ProtoEmpty` - dummy empty message
  * `AESGCMEncryptedMessage` - provides encryption and decryption 
* `STSDHECKeyExchangeMessage` - defines how to access the derived shared key

There are then common and protocol specific concrete implementations:

* Common Messages:
  * `ProtoMsgInitKeyResp(AESGCMEncryptedMessage)`
  * `ProtoMsgConfirmKeyMsg(AESGCMEncryptedMessage)`
  * `ProtoMsgConfirmKeyEncMsg(SignatureMessage)`
* Enrolment Protocol Messages:
  * `ProtoMsgInitKeyReq(SignatureMessage,STSDHECKeyExchangeMessage)`
  * `ProtoMsgInitKeyRespEncMsg(SignatureMessage)`
* Web Socket Protocol Messages:
  * `ProtoWSSInitKeyReqMsg(SignatureMessage,STSDHECKeyExchangeMessage )`
  * `ProtoWSSInitKeyRespEncMsg(SignatureMessage)`
* Core Protocol Message
  * `ProtoMsgCoreMsg(AESGCMEncryptedMessage)`
  * `ProtoMsgCoreRespMsg(AESGCMEncryptedMessage)`
  * `ProtoMsgCoreEncMsg(SignatureMessage)`
* Error Messages
  * `ProtoErrorMsg`
  * `ProtoErrorEncMsg(SignatureMessage)`

Each protocol specified message will reference Enums that contain lists of fields to be expected or used by that protocol message. For example, all messages will reference a Fields Enum that contains a list of fields that the JSON representation of that message must contain. This information is used to verify the message is of the correct type. Signature messages will also contain a reference to signature fields, which determines which fields should be included, and in what order, inside the generated signature. It is this combination of reference Enums that allows the SignatureMessage class to handle the signing and verification of all signed messages, even though the contents of their signatures vary.

These messages are combined by the Protocol classes to represent the protocol message exchange.

### Protocols
Protocols are implemented using a similar approach with functionality defined by an abstract `Protocol` class and then specified extensions for the different protocols. The protocols contain an array of messages that constitute the full message exchange associated with that protocol. The protocol class operates like a finite state machine in that it moves from one message state to another as it is either received or sent. Any messages that do not conform to the current state are dropped. 

Implemented Abstract Protocols:
* `Protocol`
  * `STSDHKeyExchangeProtocol`
    * `STSDHKEwithAESGCMEncrypedMessageProtocol`

The above subclass each other to build functionality. Protocol provides the most basic common functionality. The `STSDHKeyExchangeProtocol` provides the functionality required during the STS key exchange, whilst the `STSDHKEwithAESGCMEncrypedMessageProtocol` provides the functionality required to utilise the derived key from the `STSDHKeyExchangeProtocol` in exchanging encrypted messages.

Implemented Concrete Protocols:
* `EnrolmentProtocol(STSDHKEwithAESGCMEncrypedMessageProtocol)`
* `WSSKeyExchangeProtocol(STSDHKEwithAESGCMEncrypedMessageProtocol)`

The two most important functions that the concrete protocols should implement is:
* `process_outgoing_message(self, message:ProtocolMessage)`
  * Processes an outgoing message before it is sent, for example, adding additional data to it, generating values, etc.
* `process_incoming_message(self, message:ProtocolMessage)`
  * Process an incoming message, for example, storing received values, performing key derivation, etc.

There is reasonably extension processing in these two methods to handle different message types as they are received. Some of this functionality could be further generalised and the overall structure improved in future implementations. The Android App, albeit written in a different language, already exhibits the next iteration of the concept and provides a cleaner approach.

## Building the Library
Run the following to build the wheel
```bash
python3 setup.py bdist_wheel --universal
```
Note, this approach to building should be updated to use new tools like pip, but is sufficient for our current development builds. To change the version numbering modify setup.py

```python
from setuptools import setup

setup(
    name='Compendium',
    version='0.2',
    packages=['.compendium', 'compendium.wss'],
)
```
If requirements have changed create a new requirements.txt using:

```bash
pip freeze > requirements.txt
```

The built wheel is in `./dist/`
   

   
    
