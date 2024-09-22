import base64
import enum
import struct
import dns.dnssectypes
import dns.exception
import dns.immutable
import dns.rdata
__all__ = ['SEP', 'REVOKE', 'ZONE']


class Flag(enum.IntFlag):
    SEP = 1
    REVOKE = 128
    ZONE = 256


@dns.immutable.immutable
class DNSKEYBase(dns.rdata.Rdata):
    """Base class for rdata that is like a DNSKEY record"""
    __slots__ = ['flags', 'protocol', 'algorithm', 'key']

    def __init__(self, rdclass, rdtype, flags, protocol, algorithm, key):
        super().__init__(rdclass, rdtype)
        self.flags = Flag(self._as_uint16(flags))
        self.protocol = self._as_uint8(protocol)
        self.algorithm = dns.dnssectypes.Algorithm.make(algorithm)
        self.key = self._as_bytes(key)


SEP = Flag.SEP
REVOKE = Flag.REVOKE
ZONE = Flag.ZONE
