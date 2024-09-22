import struct
import dns.exception
import dns.immutable
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class HINFO(dns.rdata.Rdata):
    """HINFO record"""
    __slots__ = ['cpu', 'os']

    def __init__(self, rdclass, rdtype, cpu, os):
        super().__init__(rdclass, rdtype)
        self.cpu = self._as_bytes(cpu, True, 255)
        self.os = self._as_bytes(os, True, 255)
