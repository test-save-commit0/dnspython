import dns.exception
import dns.immutable
import dns.ipv4
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class A(dns.rdata.Rdata):
    """A record."""
    __slots__ = ['address']

    def __init__(self, rdclass, rdtype, address):
        super().__init__(rdclass, rdtype)
        self.address = self._as_ipv4_address(address)
