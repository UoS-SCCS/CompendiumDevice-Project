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
import json
from enum import Enum


class MSG(Enum):
    """Base fields in all messages
    """
    TYPE = "type"


class TYPE(Enum):
    """List of message types
    """
    INIT = "INIT"
    INITRESP = "INITRESP"
    ROUTE = "ROUTE"
    DELIVER = "DELIVER"
    ERROR = "ERR"


class INIT(Enum):
    """INIT message fields in addition MSG fields

    In this case there are none
    """
    pass


class INITRESP(Enum):
    """INITRESP message fields in addition to MSG fields
    Currently only the ephemeral address.
    """
    ADR = "EpheWssAddr"


class ROUTE(Enum):
    """ROUTE message fields in addition to MSG fields
    Currently only the ephemeral address and the message
    """
    ADR = "EpheWssAddr"
    MSG = "msg"


class DELIVER(Enum):
    """DELIVER message fields in addition to MSG fields
    Currently only the message field
    """
    MSG = "msg"


class ERROR(Enum):
    """ERROR message fields in addition to MSG fields
    Currently only the error code and message
    """
    CODE = "errCode"
    MSG = "errMsg"


# Dictionary mapping TYPE init to specific Enum with those fields
# Used to generalise field validation
MSGTYPES = {TYPE.INIT: INIT, TYPE.ROUTE: ROUTE, TYPE.ERROR: ERROR,
            TYPE.INITRESP: INITRESP, TYPE.DELIVER: DELIVER}


class Message(dict):
    """Generic message object

    Args:
        dict (): supertype
    """

    def __init__(self, *args, **kwargs):
        """Initialise and then validate. As such partial initialisation
        is not permitted
        """
        self.update(*args, **kwargs)
        self._validate()

    def get_type(self) -> MSG.TYPE:
        """Gets the message type

        Returns:
            MSG.TYPE: Type of the message
        """
        return TYPE(self[MSG.TYPE.value])

    def encode(self) -> str:
        """Gets a JSON string representation of this dictionary

        Returns:
            str: JSON String representation
        """
        return json.dumps(self)

    def encode_as_bytes(self) -> bytes:
        """Gets a JSON string representation and then encodes it
        to bytes using UTF-8

        Returns:
            bytes: UTF-8 byte encoding of JSON string representation
        """
        return json.dumps(self).encode('utf-8')

    def get_field_value(self, field: str) -> str:
        """Gets a string field value.   

        Args:
            field (str): field to retrieve

        Returns:
            str: value of specified field
        """
        return self[field]

    def _validate(self):
        """Validates the contents of this dictionary against a 
        combination of the generic MSG fields and the specified
        fields determined by the message TYPE

        Raises:
            Exception: If fields are missing
        """
        # Generic generic MSG fields
        for field in MSG:
            if(field.value not in self):
                raise Exception("Missing message field:" + field.value)

        # We know it must have a type so retrieve it
        self.type = TYPE(self[MSG.TYPE.value])

        # Check type specific fields
        self._validate_content(MSGTYPES[self.type])

    def _validate_content(self, type: Enum):
        """Validate the type specific fields in the specified
        type Enum

        Also sets the fields as attributes on the object
        for easier access.

        Args:
            type (Enum): Type of message to validate

        Raises:
            Exception: If message fields are missing
        """
        for field in type:
            if(field.value not in self):
                raise Exception("Missing message field:" + field.value)
            else:
                setattr(self, field.value, self[field.value])

    @staticmethod
    def create_init() -> "Message":
        """Create an INIT message

        Returns:
            Message: INIT message
        """
        return Message({MSG.TYPE.value: TYPE.INIT.value})

    @staticmethod
    def create_init_response(EpheWssAddr: str) -> "Message":
        """Creates an INITRESP with the specified address

        Args:
            EpheWssAddr (str): Address to respond with

        Returns:
            Message: INITRESP message
        """
        return Message({MSG.TYPE.value: TYPE.INITRESP.value, INITRESP.ADR.value: EpheWssAddr})

    @staticmethod
    def create_deliver(msg: "Message") -> "Message":
        """Creates a DELIVER message with the specified message

        This takes the Message object received through a ROUTE
        and moves it to a DELIVER message to be sent to the final
        recipient

        Args:
            msg (Message): message to be delivered

        Returns:
            Message: Message to be delivered
        """
        return Message({MSG.TYPE.value: TYPE.DELIVER.value, DELIVER.MSG.value: msg[ROUTE.MSG.value]})

    @staticmethod
    def create_error(errCode: int, errMsg: str = None) -> "Message":
        """Creates an error message

        Args:
            errCode (int): error code
            errMsg (str, optional): error message. Defaults to None.

        Returns:
            Message: error message
        """
        return Message({MSG.TYPE.value: TYPE.ERROR.value, ERROR.CODE.value: errCode, ERROR.MSG.value: errMsg})

    @staticmethod
    def create_route(EpheWssAddr: str, msg: dict) -> "Message":
        """Creates a ROUTE message with the specified address and 
        message

        Args:
            EpheWssAddr (str): target address
            msg (dict): message to be sent

        Returns:
            Message: _description_
        """
        return Message({MSG.TYPE.value: TYPE.ROUTE.value, ROUTE.ADR.value: EpheWssAddr, ROUTE.MSG.value: msg})

    @staticmethod
    def parse(message_str: str) -> "Message":
        """Parse the specified string reprensentation of a message and
        return a Message object. message_str should a JSON string
        containing a valid Message representation.

        Args:
            message_str (str): JSON String containing a valid message

        Returns:
            Message: Message object initialised with message_str
        """
        return Message(json.loads(message_str))
