import binascii
import struct
import dns.exception
import dns.immutable
import dns.rdata


@dns.immutable.immutable
class NSEC3PARAM(dns.rdata.Rdata):
    """NSEC3PARAM record"""
    __slots__ = ['algorithm', 'flags', 'iterations', 'salt']

    def __init__(self, rdclass, rdtype, algorithm, flags, iterations, salt):
        super().__init__(rdclass, rdtype)
        self.algorithm = self._as_uint8(algorithm)
        self.flags = self._as_uint8(flags)
        self.iterations = self._as_uint16(iterations)
        self.salt = self._as_bytes(salt, True, 255)
