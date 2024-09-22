import binascii
import struct
import dns.dnssectypes
import dns.immutable
import dns.rdata
import dns.rdatatype


@dns.immutable.immutable
class DSBase(dns.rdata.Rdata):
    """Base class for rdata that is like a DS record"""
    __slots__ = ['key_tag', 'algorithm', 'digest_type', 'digest']
    _digest_length_by_type = {(1): 20, (2): 32, (3): 32, (4): 48}

    def __init__(self, rdclass, rdtype, key_tag, algorithm, digest_type, digest
        ):
        super().__init__(rdclass, rdtype)
        self.key_tag = self._as_uint16(key_tag)
        self.algorithm = dns.dnssectypes.Algorithm.make(algorithm)
        self.digest_type = dns.dnssectypes.DSDigest.make(self._as_uint8(
            digest_type))
        self.digest = self._as_bytes(digest)
        try:
            if len(self.digest) != self._digest_length_by_type[self.digest_type
                ]:
                raise ValueError('digest length inconsistent with digest type')
        except KeyError:
            if self.digest_type == 0:
                raise ValueError('digest type 0 is reserved')
