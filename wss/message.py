import json
from enum import Enum

class MSG(Enum):
    TYPE = "type"

class TYPE(Enum):
    INIT = "INIT"
    INITRESP = "INITRESP"
    ROUTE = "ROUTE"
    DELIVER = "DELIVER"
    ERROR = "ERR"

class INIT(Enum):
    pass

class INITRESP(Enum):
    ADR = "EpheWssAddr"

class ROUTE(Enum):
    ADR = "EpheWssAddr"
    MSG = "msg"

class DELIVER(Enum):
    MSG = "msg"

class ERROR(Enum):
    CODE = "errCode"
    MSG = "errMsg"

MSGTYPES={TYPE.INIT:INIT,TYPE.ROUTE:ROUTE,TYPE.ERROR:ERROR,TYPE.INITRESP:INITRESP, TYPE.DELIVER:DELIVER}

class Message(dict):
    """Generic message object

    Args:
        dict (): supertype
    """


    def __init__(self, *args, **kwargs):#json=None, EpheWssAddr=None, msg=None
        self.update(*args, **kwargs)
        self._validate()

    def get_type(self)->MSG.TYPE:
        return TYPE(self[MSG.TYPE.value])
    def encode(self)->str:
        return json.dumps(self)
    def encode_as_bytes(self)->bytes:
        return json.dumps(self).encode('utf-8')
    def _validate(self):
        for field in MSG:
            if(field.value not in self):
                raise Exception("Missing message field:" + field.value)

        self.type = TYPE(self[MSG.TYPE.value])
        self._validate_content(MSGTYPES[self.type])

    def _validate_content(self, type:Enum):
        for field in type:
            if(field.value not in self):
                raise Exception("Missing message field:" + field.value)
            else:
                setattr(self,field.value,self[field.value])

    @staticmethod
    def create_init()->"Message":
        return Message({MSG.TYPE.value:TYPE.INIT.value})
    @staticmethod
    def create_init_response(EpheWssAddr:str)->"Message":
        return Message({MSG.TYPE.value:TYPE.INITRESP.value,INITRESP.ADR.value:EpheWssAddr})
    @staticmethod
    def create_deliver(msg:"Message")->"Message":
        return Message({MSG.TYPE.value:TYPE.DELIVER.value,DELIVER.MSG.value:msg[ROUTE.MSG.value]})
    @staticmethod
    def create_error(errCode:int, errMsg:str=None)->"Message":
        return Message({MSG.TYPE.value:TYPE.ERROR.value,ERROR.CODE.value:errCode,ERROR.MSG.value:errMsg})

    @staticmethod
    def create_route(EpheWssAddr:str,msg:dict)->"Message":
        return Message({MSG.TYPE.value:TYPE.ROUTE.value,ROUTE.ADR.value:EpheWssAddr,ROUTE.MSG.value:msg})

    @staticmethod
    def parse(message_str:str)->"Message":
        return Message(json.loads(message_str))

