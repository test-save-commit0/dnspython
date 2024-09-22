import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, utils
from dns.dnssecalgs.cryptography import CryptographyPrivateKey, CryptographyPublicKey
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


class PublicDSA(CryptographyPublicKey):
    key: dsa.DSAPublicKey
    key_cls = dsa.DSAPublicKey
    algorithm = Algorithm.DSA
    chosen_hash = hashes.SHA1()

    def encode_key_bytes(self) ->bytes:
        """Encode a public key per RFC 2536, section 2."""
        pass


class PrivateDSA(CryptographyPrivateKey):
    key: dsa.DSAPrivateKey
    key_cls = dsa.DSAPrivateKey
    public_cls = PublicDSA

    def sign(self, data: bytes, verify: bool=False) ->bytes:
        """Sign using a private key per RFC 2536, section 3."""
        pass


class PublicDSANSEC3SHA1(PublicDSA):
    algorithm = Algorithm.DSANSEC3SHA1


class PrivateDSANSEC3SHA1(PrivateDSA):
    public_cls = PublicDSANSEC3SHA1
