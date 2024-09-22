import base64
import struct
import dns.exception
import dns.immutable
import dns.rdtypes.util


class Gateway(dns.rdtypes.util.Gateway):
    name = 'IPSECKEY gateway'


@dns.immutable.immutable
class IPSECKEY(dns.rdata.Rdata):
    """IPSECKEY record"""
    __slots__ = ['precedence', 'gateway_type', 'algorithm', 'gateway', 'key']

    def __init__(self, rdclass, rdtype, precedence, gateway_type, algorithm,
        gateway, key):
        super().__init__(rdclass, rdtype)
        gateway = Gateway(gateway_type, gateway)
        self.precedence = self._as_uint8(precedence)
        self.gateway_type = gateway.type
        self.algorithm = self._as_uint8(algorithm)
        self.gateway = gateway.gateway
        self.key = self._as_bytes(key)
