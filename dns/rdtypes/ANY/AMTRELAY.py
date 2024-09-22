import struct
import dns.exception
import dns.immutable
import dns.rdtypes.util


class Relay(dns.rdtypes.util.Gateway):
    name = 'AMTRELAY relay'


@dns.immutable.immutable
class AMTRELAY(dns.rdata.Rdata):
    """AMTRELAY record"""
    __slots__ = ['precedence', 'discovery_optional', 'relay_type', 'relay']

    def __init__(self, rdclass, rdtype, precedence, discovery_optional,
        relay_type, relay):
        super().__init__(rdclass, rdtype)
        relay = Relay(relay_type, relay)
        self.precedence = self._as_uint8(precedence)
        self.discovery_optional = self._as_bool(discovery_optional)
        self.relay_type = relay.type
        self.relay = relay.relay
