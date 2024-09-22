import struct
import dns.immutable
import dns.rdata


@dns.immutable.immutable
class L32(dns.rdata.Rdata):
    """L32 record"""
    __slots__ = ['preference', 'locator32']

    def __init__(self, rdclass, rdtype, preference, locator32):
        super().__init__(rdclass, rdtype)
        self.preference = self._as_uint16(preference)
        self.locator32 = self._as_ipv4_address(locator32)
