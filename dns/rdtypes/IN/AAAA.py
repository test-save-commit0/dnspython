import dns.exception
import dns.immutable
import dns.ipv6
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class AAAA(dns.rdata.Rdata):
    """AAAA record."""
    __slots__ = ['address']

    def __init__(self, rdclass, rdtype, address):
        super().__init__(rdclass, rdtype)
        self.address = self._as_ipv6_address(address)
