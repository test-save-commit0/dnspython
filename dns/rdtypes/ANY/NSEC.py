import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdatatype
import dns.rdtypes.util


@dns.immutable.immutable
class Bitmap(dns.rdtypes.util.Bitmap):
    type_name = 'NSEC'


@dns.immutable.immutable
class NSEC(dns.rdata.Rdata):
    """NSEC record"""
    __slots__ = ['next', 'windows']

    def __init__(self, rdclass, rdtype, next, windows):
        super().__init__(rdclass, rdtype)
        self.next = self._as_name(next)
        if not isinstance(windows, Bitmap):
            windows = Bitmap(windows)
        self.windows = tuple(windows.windows)
