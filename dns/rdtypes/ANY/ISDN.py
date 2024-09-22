import struct
import dns.exception
import dns.immutable
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class ISDN(dns.rdata.Rdata):
    """ISDN record"""
    __slots__ = ['address', 'subaddress']

    def __init__(self, rdclass, rdtype, address, subaddress):
        super().__init__(rdclass, rdtype)
        self.address = self._as_bytes(address, True, 255)
        self.subaddress = self._as_bytes(subaddress, True, 255)
