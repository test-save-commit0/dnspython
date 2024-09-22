import binascii
import dns.immutable
import dns.rdata


@dns.immutable.immutable
class EUIBase(dns.rdata.Rdata):
    """EUIxx record"""
    __slots__ = ['eui']

    def __init__(self, rdclass, rdtype, eui):
        super().__init__(rdclass, rdtype)
        self.eui = self._as_bytes(eui)
        if len(self.eui) != self.byte_len:
            raise dns.exception.FormError(
                'EUI%s rdata has to have %s bytes' % (self.byte_len * 8,
                self.byte_len))
