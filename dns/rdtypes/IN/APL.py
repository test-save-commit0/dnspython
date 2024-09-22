import binascii
import codecs
import struct
import dns.exception
import dns.immutable
import dns.ipv4
import dns.ipv6
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class APLItem:
    """An APL list item."""
    __slots__ = ['family', 'negation', 'address', 'prefix']

    def __init__(self, family, negation, address, prefix):
        self.family = dns.rdata.Rdata._as_uint16(family)
        self.negation = dns.rdata.Rdata._as_bool(negation)
        if self.family == 1:
            self.address = dns.rdata.Rdata._as_ipv4_address(address)
            self.prefix = dns.rdata.Rdata._as_int(prefix, 0, 32)
        elif self.family == 2:
            self.address = dns.rdata.Rdata._as_ipv6_address(address)
            self.prefix = dns.rdata.Rdata._as_int(prefix, 0, 128)
        else:
            self.address = dns.rdata.Rdata._as_bytes(address, max_length=127)
            self.prefix = dns.rdata.Rdata._as_uint8(prefix)

    def __str__(self):
        if self.negation:
            return '!%d:%s/%s' % (self.family, self.address, self.prefix)
        else:
            return '%d:%s/%s' % (self.family, self.address, self.prefix)


@dns.immutable.immutable
class APL(dns.rdata.Rdata):
    """APL record."""
    __slots__ = ['items']

    def __init__(self, rdclass, rdtype, items):
        super().__init__(rdclass, rdtype)
        for item in items:
            if not isinstance(item, APLItem):
                raise ValueError('item not an APLItem')
        self.items = tuple(items)
