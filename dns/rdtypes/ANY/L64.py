import struct
import dns.immutable
import dns.rdtypes.util


@dns.immutable.immutable
class L64(dns.rdata.Rdata):
    """L64 record"""
    __slots__ = ['preference', 'locator64']

    def __init__(self, rdclass, rdtype, preference, locator64):
        super().__init__(rdclass, rdtype)
        self.preference = self._as_uint16(preference)
        if isinstance(locator64, bytes):
            if len(locator64) != 8:
                raise ValueError('invalid locator64')
            self.locator64 = dns.rdata._hexify(locator64, 4, b':')
        else:
            dns.rdtypes.util.parse_formatted_hex(locator64, 4, 4, ':')
            self.locator64 = locator64
