import struct
import dns.exception
import dns.immutable
import dns.name
import dns.rdata


@dns.immutable.immutable
class SOA(dns.rdata.Rdata):
    """SOA record"""
    __slots__ = ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire',
        'minimum']

    def __init__(self, rdclass, rdtype, mname, rname, serial, refresh,
        retry, expire, minimum):
        super().__init__(rdclass, rdtype)
        self.mname = self._as_name(mname)
        self.rname = self._as_name(rname)
        self.serial = self._as_uint32(serial)
        self.refresh = self._as_ttl(refresh)
        self.retry = self._as_ttl(retry)
        self.expire = self._as_ttl(expire)
        self.minimum = self._as_ttl(minimum)
