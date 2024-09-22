import struct
import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdtypes.util


@dns.immutable.immutable
class URI(dns.rdata.Rdata):
    """URI record"""
    __slots__ = ['priority', 'weight', 'target']

    def __init__(self, rdclass, rdtype, priority, weight, target):
        super().__init__(rdclass, rdtype)
        self.priority = self._as_uint16(priority)
        self.weight = self._as_uint16(weight)
        self.target = self._as_bytes(target, True)
        if len(self.target) == 0:
            raise dns.exception.SyntaxError('URI target cannot be empty')
