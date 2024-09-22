from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from dns.dnssecalgs.cryptography import CryptographyPrivateKey, CryptographyPublicKey
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


class PublicECDSA(CryptographyPublicKey):
    key: ec.EllipticCurvePublicKey
    key_cls = ec.EllipticCurvePublicKey
    algorithm: Algorithm
    chosen_hash: hashes.HashAlgorithm
    curve: ec.EllipticCurve
    octets: int

    def encode_key_bytes(self) ->bytes:
        """Encode a public key per RFC 6605, section 4."""
        pass


class PrivateECDSA(CryptographyPrivateKey):
    key: ec.EllipticCurvePrivateKey
    key_cls = ec.EllipticCurvePrivateKey
    public_cls = PublicECDSA

    def sign(self, data: bytes, verify: bool=False) ->bytes:
        """Sign using a private key per RFC 6605, section 4."""
        pass


class PublicECDSAP256SHA256(PublicECDSA):
    algorithm = Algorithm.ECDSAP256SHA256
    chosen_hash = hashes.SHA256()
    curve = ec.SECP256R1()
    octets = 32


class PrivateECDSAP256SHA256(PrivateECDSA):
    public_cls = PublicECDSAP256SHA256


class PublicECDSAP384SHA384(PublicECDSA):
    algorithm = Algorithm.ECDSAP384SHA384
    chosen_hash = hashes.SHA384()
    curve = ec.SECP384R1()
    octets = 48


class PrivateECDSAP384SHA384(PrivateECDSA):
    public_cls = PublicECDSAP384SHA384
