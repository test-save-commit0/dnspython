import binascii
import dns.exception
import dns.immutable
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class NSAP(dns.rdata.Rdata):
    """NSAP record."""
    __slots__ = ['address']

    def __init__(self, rdclass, rdtype, address):
        super().__init__(rdclass, rdtype)
        self.address = self._as_bytes(address)
