"""MX-like base classes."""
import struct
import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdtypes.util


@dns.immutable.immutable
class MXBase(dns.rdata.Rdata):
    """Base class for rdata that is like an MX record."""
    __slots__ = ['preference', 'exchange']

    def __init__(self, rdclass, rdtype, preference, exchange):
        super().__init__(rdclass, rdtype)
        self.preference = self._as_uint16(preference)
        self.exchange = self._as_name(exchange)


@dns.immutable.immutable
class UncompressedMX(MXBase):
    """Base class for rdata that is like an MX record, but whose name
    is not compressed when converted to DNS wire format, and whose
    digestable form is not downcased."""


@dns.immutable.immutable
class UncompressedDowncasingMX(MXBase):
    """Base class for rdata that is like an MX record, but whose name
    is not compressed when convert to DNS wire format."""
