import base64
import binascii
import struct
import dns.exception
import dns.immutable
import dns.rdata
import dns.rdatatype


@dns.immutable.immutable
class HIP(dns.rdata.Rdata):
    """HIP record"""
    __slots__ = ['hit', 'algorithm', 'key', 'servers']

    def __init__(self, rdclass, rdtype, hit, algorithm, key, servers):
        super().__init__(rdclass, rdtype)
        self.hit = self._as_bytes(hit, True, 255)
        self.algorithm = self._as_uint8(algorithm)
        self.key = self._as_bytes(key, True)
        self.servers = self._as_tuple(servers, self._as_name)
