import binascii
import struct
import dns.immutable
import dns.rdata
import dns.rdatatype


@dns.immutable.immutable
class TLSABase(dns.rdata.Rdata):
    """Base class for TLSA and SMIMEA records"""
    __slots__ = ['usage', 'selector', 'mtype', 'cert']

    def __init__(self, rdclass, rdtype, usage, selector, mtype, cert):
        super().__init__(rdclass, rdtype)
        self.usage = self._as_uint8(usage)
        self.selector = self._as_uint8(selector)
        self.mtype = self._as_uint8(mtype)
        self.cert = self._as_bytes(cert)
