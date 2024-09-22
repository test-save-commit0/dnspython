import base64
import dns.exception
import dns.immutable
import dns.rdata


@dns.immutable.immutable
class DHCID(dns.rdata.Rdata):
    """DHCID record"""
    __slots__ = ['data']

    def __init__(self, rdclass, rdtype, data):
        super().__init__(rdclass, rdtype)
        self.data = self._as_bytes(data)
