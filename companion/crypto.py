from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod

class SigningKey(ABC):
    pass

class VerificationKey(ABC):
    pass

class IdentitySigningKey(SigningKey):
    pass

class IdentityVerificationKey(SigningKey):
    pass