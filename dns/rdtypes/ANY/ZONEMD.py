import binascii
import struct
import dns.immutable
import dns.rdata
import dns.rdatatype
import dns.zonetypes


@dns.immutable.immutable
class ZONEMD(dns.rdata.Rdata):
    """ZONEMD record"""
    __slots__ = ['serial', 'scheme', 'hash_algorithm', 'digest']

    def __init__(self, rdclass, rdtype, serial, scheme, hash_algorithm, digest
        ):
        super().__init__(rdclass, rdtype)
        self.serial = self._as_uint32(serial)
        self.scheme = dns.zonetypes.DigestScheme.make(scheme)
        self.hash_algorithm = dns.zonetypes.DigestHashAlgorithm.make(
            hash_algorithm)
        self.digest = self._as_bytes(digest)
        if self.scheme == 0:
            raise ValueError('scheme 0 is reserved')
        if self.hash_algorithm == 0:
            raise ValueError('hash_algorithm 0 is reserved')
        hasher = dns.zonetypes._digest_hashers.get(self.hash_algorithm)
        if hasher and hasher().digest_size != len(self.digest):
            raise ValueError('digest length inconsistent with hash algorithm')
