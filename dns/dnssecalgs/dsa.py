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
        y = self.key.public_numbers().y
        p = self.key.public_numbers().parameter_numbers.p
        q = self.key.public_numbers().parameter_numbers.q
        g = self.key.public_numbers().parameter_numbers.g
        
        t = (p.bit_length() - 64) // 8 - 8
        
        return struct.pack("!B", t) + \
               g.to_bytes(128, 'big') + \
               y.to_bytes(128, 'big') + \
               p.to_bytes(64 + t * 8, 'big') + \
               q.to_bytes(20, 'big')


class PrivateDSA(CryptographyPrivateKey):
    key: dsa.DSAPrivateKey
    key_cls = dsa.DSAPrivateKey
    public_cls = PublicDSA

    def sign(self, data: bytes, verify: bool=False) ->bytes:
        """Sign using a private key per RFC 2536, section 3."""
        signature = self.key.sign(
            data,
            hashes.SHA1()
        )
        r, s = utils.decode_dss_signature(signature)
        
        encoded_signature = r.to_bytes(20, 'big') + s.to_bytes(20, 'big')
        
        if verify:
            self.key.public_key().verify(
                signature,
                data,
                hashes.SHA1()
            )
        
        return encoded_signature


class PublicDSANSEC3SHA1(PublicDSA):
    algorithm = Algorithm.DSANSEC3SHA1


class PrivateDSANSEC3SHA1(PrivateDSA):
    public_cls = PublicDSANSEC3SHA1
