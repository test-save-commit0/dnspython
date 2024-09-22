import base64
import struct
import dns.exception
import dns.immutable
import dns.rdata


@dns.immutable.immutable
class TKEY(dns.rdata.Rdata):
    """TKEY Record"""
    __slots__ = ['algorithm', 'inception', 'expiration', 'mode', 'error',
        'key', 'other']

    def __init__(self, rdclass, rdtype, algorithm, inception, expiration,
        mode, error, key, other=b''):
        super().__init__(rdclass, rdtype)
        self.algorithm = self._as_name(algorithm)
        self.inception = self._as_uint32(inception)
        self.expiration = self._as_uint32(expiration)
        self.mode = self._as_uint16(mode)
        self.error = self._as_uint16(error)
        self.key = self._as_bytes(key)
        self.other = self._as_bytes(other)
    SERVER_ASSIGNMENT = 1
    DIFFIE_HELLMAN_EXCHANGE = 2
    GSSAPI_NEGOTIATION = 3
    RESOLVER_ASSIGNMENT = 4
    KEY_DELETION = 5
