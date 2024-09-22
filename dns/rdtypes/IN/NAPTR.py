import struct
import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdtypes.util


@dns.immutable.immutable
class NAPTR(dns.rdata.Rdata):
    """NAPTR record"""
    __slots__ = ['order', 'preference', 'flags', 'service', 'regexp',
        'replacement']

    def __init__(self, rdclass, rdtype, order, preference, flags, service,
        regexp, replacement):
        super().__init__(rdclass, rdtype)
        self.flags = self._as_bytes(flags, True, 255)
        self.service = self._as_bytes(service, True, 255)
        self.regexp = self._as_bytes(regexp, True, 255)
        self.order = self._as_uint16(order)
        self.preference = self._as_uint16(preference)
        self.replacement = self._as_name(replacement)
