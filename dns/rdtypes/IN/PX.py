import struct
import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdtypes.util


@dns.immutable.immutable
class PX(dns.rdata.Rdata):
    """PX record."""
    __slots__ = ['preference', 'map822', 'mapx400']

    def __init__(self, rdclass, rdtype, preference, map822, mapx400):
        super().__init__(rdclass, rdtype)
        self.preference = self._as_uint16(preference)
        self.map822 = self._as_name(map822)
        self.mapx400 = self._as_name(mapx400)
