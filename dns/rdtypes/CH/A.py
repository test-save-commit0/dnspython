import struct
import dns.immutable
import dns.rdtypes.mxbase


@dns.immutable.immutable
class A(dns.rdata.Rdata):
    """A record for Chaosnet"""
    __slots__ = ['domain', 'address']

    def __init__(self, rdclass, rdtype, domain, address):
        super().__init__(rdclass, rdtype)
        self.domain = self._as_name(domain)
        self.address = self._as_uint16(address)
