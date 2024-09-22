import socket
import struct
import dns.immutable
import dns.ipv4
import dns.rdata
try:
    _proto_tcp = socket.getprotobyname('tcp')
    _proto_udp = socket.getprotobyname('udp')
except OSError:
    _proto_tcp = 6
    _proto_udp = 17


@dns.immutable.immutable
class WKS(dns.rdata.Rdata):
    """WKS record"""
    __slots__ = ['address', 'protocol', 'bitmap']

    def __init__(self, rdclass, rdtype, address, protocol, bitmap):
        super().__init__(rdclass, rdtype)
        self.address = self._as_ipv4_address(address)
        self.protocol = self._as_uint8(protocol)
        self.bitmap = self._as_bytes(bitmap)
