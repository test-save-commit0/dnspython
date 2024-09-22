import struct
import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdatatype
import dns.rdtypes.util


@dns.immutable.immutable
class Bitmap(dns.rdtypes.util.Bitmap):
    type_name = 'CSYNC'


@dns.immutable.immutable
class CSYNC(dns.rdata.Rdata):
    """CSYNC record"""
    __slots__ = ['serial', 'flags', 'windows']

    def __init__(self, rdclass, rdtype, serial, flags, windows):
        super().__init__(rdclass, rdtype)
        self.serial = self._as_uint32(serial)
        self.flags = self._as_uint16(flags)
        if not isinstance(windows, Bitmap):
            windows = Bitmap(windows)
        self.windows = tuple(windows.windows)
