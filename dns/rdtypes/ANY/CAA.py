import struct
import dns.exception
import dns.immutable
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class CAA(dns.rdata.Rdata):
    """CAA (Certification Authority Authorization) record"""
    __slots__ = ['flags', 'tag', 'value']

    def __init__(self, rdclass, rdtype, flags, tag, value):
        super().__init__(rdclass, rdtype)
        self.flags = self._as_uint8(flags)
        self.tag = self._as_bytes(tag, True, 255)
        if not tag.isalnum():
            raise ValueError('tag is not alphanumeric')
        self.value = self._as_bytes(value)
