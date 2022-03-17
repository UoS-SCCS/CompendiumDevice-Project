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
import base64
from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          PublicFormat)

#Constants for detecting PEM encoded keys
PEM_HEAD = "-----BEGIN PUBLIC KEY-----"
PEM_TAIL = "-----END PUBLIC KEY-----"


class CryptoUtils():
    """Provides static crypto util functions
    """
    @staticmethod
    def load_public_key_from_string(public_key_str:str)->EllipticCurvePublicKey:
        """Loads a public key from an encoded public key string

        Args:
            public_key_str (str): Base64 encoded public key

        Returns:
            EllipticCurvePublicKey: public key
        """
        if public_key_str.startswith(PEM_HEAD):
            return serialization.load_pem_public_key(public_key_str.encode("UTF-8"))
        else:
            return serialization.load_der_public_key(B64.decode(public_key_str))

    def public_key_to_string(public_key:EllipticCurvePublicKey)->str:
        """Encodes the public key as Base64 encoded DER representation of
        the public key bytes    

        Args:
            public_key (EllipticCurvePublicKey): public key to encode

        Returns:
            str: Base64 DER encoded public key bytes
        """
        return B64.encode(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))

    @staticmethod
    def get_public_key_identifier(key:Union[EllipticCurvePublicKey, str]) -> str:
        """Calculates the public key identifier, which is the SHA256
        hash of the DER encoded public key bytes

        Args:
            key (EllipticCurvePublicKey|str): public key to calculate identifier for

        Returns:
            str: Base64 encoded public key ID
        """
        if not isinstance(key, EllipticCurvePublicKey):
            temp_key = CryptoUtils.load_public_key_from_string(key)
        else:
            temp_key = key
        temp_bytes = temp_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(temp_bytes)
        return hasher.finalize().hex()


class B64():
    """Wrapper around the Base64 encoder and decoder

    Handles encoding and decoding to UTF-8 to improve
    code readability.

    
    """
    @staticmethod
    def encode(data: bytes) -> str:
        """Encodes bytes as Base64 and returns a string

        Args:
            data (bytes): bytes to encode

        Returns:
            str: Base64 string encoding of bytes
        """
        return base64.b64encode(data).decode("UTF-8")

    @staticmethod
    def decode(b64string: str) -> bytes:
        """Decodes a Base64 encoded string to bytes

        Args:
            b64string (str): Base64 encoded string

        Returns:
            bytes: decoded bytes
        """
        return base64.decodebytes(b64string.encode("UTF-8"))
