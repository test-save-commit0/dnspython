import dns.exception
import dns.immutable
import dns.name
import dns.rdata


@dns.immutable.immutable
class RP(dns.rdata.Rdata):
    """RP record"""
    __slots__ = ['mbox', 'txt']

    def __init__(self, rdclass, rdtype, mbox, txt):
        super().__init__(rdclass, rdtype)
        self.mbox = self._as_name(mbox)
        self.txt = self._as_name(txt)
