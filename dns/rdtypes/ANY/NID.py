import struct
import dns.immutable
import dns.rdtypes.util


@dns.immutable.immutable
class NID(dns.rdata.Rdata):
    """NID record"""
    __slots__ = ['preference', 'nodeid']

    def __init__(self, rdclass, rdtype, preference, nodeid):
        super().__init__(rdclass, rdtype)
        self.preference = self._as_uint16(preference)
        if isinstance(nodeid, bytes):
            if len(nodeid) != 8:
                raise ValueError('invalid nodeid')
            self.nodeid = dns.rdata._hexify(nodeid, 4, b':')
        else:
            dns.rdtypes.util.parse_formatted_hex(nodeid, 4, 4, ':')
            self.nodeid = nodeid
