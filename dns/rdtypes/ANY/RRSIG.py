import base64
import calendar
import struct
import time
import dns.dnssectypes
import dns.exception
import dns.immutable
import dns.rdata
import dns.rdatatype


class BadSigTime(dns.exception.DNSException):
    """Time in DNS SIG or RRSIG resource record cannot be parsed."""


@dns.immutable.immutable
class RRSIG(dns.rdata.Rdata):
    """RRSIG record"""
    __slots__ = ['type_covered', 'algorithm', 'labels', 'original_ttl',
        'expiration', 'inception', 'key_tag', 'signer', 'signature']

    def __init__(self, rdclass, rdtype, type_covered, algorithm, labels,
        original_ttl, expiration, inception, key_tag, signer, signature):
        super().__init__(rdclass, rdtype)
        self.type_covered = self._as_rdatatype(type_covered)
        self.algorithm = dns.dnssectypes.Algorithm.make(algorithm)
        self.labels = self._as_uint8(labels)
        self.original_ttl = self._as_ttl(original_ttl)
        self.expiration = self._as_uint32(expiration)
        self.inception = self._as_uint32(inception)
        self.key_tag = self._as_uint16(key_tag)
        self.signer = self._as_name(signer)
        self.signature = self._as_bytes(signature)
