import base64
import binascii
import struct
import dns.exception
import dns.immutable
import dns.rdata
import dns.rdatatype
import dns.rdtypes.util
b32_hex_to_normal = bytes.maketrans(b'0123456789ABCDEFGHIJKLMNOPQRSTUV',
    b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
b32_normal_to_hex = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    b'0123456789ABCDEFGHIJKLMNOPQRSTUV')
SHA1 = 1
OPTOUT = 1


@dns.immutable.immutable
class Bitmap(dns.rdtypes.util.Bitmap):
    type_name = 'NSEC3'


@dns.immutable.immutable
class NSEC3(dns.rdata.Rdata):
    """NSEC3 record"""
    __slots__ = ['algorithm', 'flags', 'iterations', 'salt', 'next', 'windows']

    def __init__(self, rdclass, rdtype, algorithm, flags, iterations, salt,
        next, windows):
        super().__init__(rdclass, rdtype)
        self.algorithm = self._as_uint8(algorithm)
        self.flags = self._as_uint8(flags)
        self.iterations = self._as_uint16(iterations)
        self.salt = self._as_bytes(salt, True, 255)
        self.next = self._as_bytes(next, True, 255)
        if not isinstance(windows, Bitmap):
            windows = Bitmap(windows)
        self.windows = tuple(windows.windows)
