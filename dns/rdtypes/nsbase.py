"""NS-like base classes."""
import dns.exception
import dns.immutable
import dns.name
import dns.rdata


@dns.immutable.immutable
class NSBase(dns.rdata.Rdata):
    """Base class for rdata that is like an NS record."""
    __slots__ = ['target']

    def __init__(self, rdclass, rdtype, target):
        super().__init__(rdclass, rdtype)
        self.target = self._as_name(target)


@dns.immutable.immutable
class UncompressedNS(NSBase):
    """Base class for rdata that is like an NS record, but whose name
    is not compressed when convert to DNS wire format, and whose
    digestable form is not downcased."""
