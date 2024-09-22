from typing import Any, Optional, Type
from cryptography.hazmat.primitives import serialization
from dns.dnssecalgs.base import GenericPrivateKey, GenericPublicKey
from dns.exception import AlgorithmKeyMismatch


class CryptographyPublicKey(GenericPublicKey):
    key: Any = None
    key_cls: Any = None

    def __init__(self, key: Any) ->None:
        if self.key_cls is None:
            raise TypeError('Undefined private key class')
        if not isinstance(key, self.key_cls):
            raise AlgorithmKeyMismatch
        self.key = key


class CryptographyPrivateKey(GenericPrivateKey):
    key: Any = None
    key_cls: Any = None
    public_cls: Type[CryptographyPublicKey]

    def __init__(self, key: Any) ->None:
        if self.key_cls is None:
            raise TypeError('Undefined private key class')
        if not isinstance(key, self.key_cls):
            raise AlgorithmKeyMismatch
        self.key = key
