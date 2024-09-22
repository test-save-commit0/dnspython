import struct
import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdtypes.util


@dns.immutable.immutable
class SRV(dns.rdata.Rdata):
    """SRV record"""
    __slots__ = ['priority', 'weight', 'port', 'target']

    def __init__(self, rdclass, rdtype, priority, weight, port, target):
        super().__init__(rdclass, rdtype)
        self.priority = self._as_uint16(priority)
        self.weight = self._as_uint16(weight)
        self.port = self._as_uint16(port)
        self.target = self._as_name(target)
