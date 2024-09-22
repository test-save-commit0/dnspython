import base64
import struct
import dns.dnssectypes
import dns.exception
import dns.immutable
import dns.rdata
import dns.tokenizer
_ctype_by_value = {(1): 'PKIX', (2): 'SPKI', (3): 'PGP', (4): 'IPKIX', (5):
    'ISPKI', (6): 'IPGP', (7): 'ACPKIX', (8): 'IACPKIX', (253): 'URI', (254
    ): 'OID'}
_ctype_by_name = {'PKIX': 1, 'SPKI': 2, 'PGP': 3, 'IPKIX': 4, 'ISPKI': 5,
    'IPGP': 6, 'ACPKIX': 7, 'IACPKIX': 8, 'URI': 253, 'OID': 254}


@dns.immutable.immutable
class CERT(dns.rdata.Rdata):
    """CERT record"""
    __slots__ = ['certificate_type', 'key_tag', 'algorithm', 'certificate']

    def __init__(self, rdclass, rdtype, certificate_type, key_tag,
        algorithm, certificate):
        super().__init__(rdclass, rdtype)
        self.certificate_type = self._as_uint16(certificate_type)
        self.key_tag = self._as_uint16(key_tag)
        self.algorithm = self._as_uint8(algorithm)
        self.certificate = self._as_bytes(certificate)
