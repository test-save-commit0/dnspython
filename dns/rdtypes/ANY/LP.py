import struct
import dns.immutable
import dns.rdata


@dns.immutable.immutable
class LP(dns.rdata.Rdata):
    """LP record"""
    __slots__ = ['preference', 'fqdn']

    def __init__(self, rdclass, rdtype, preference, fqdn):
        super().__init__(rdclass, rdtype)
        self.preference = self._as_uint16(preference)
        self.fqdn = self._as_name(fqdn)
