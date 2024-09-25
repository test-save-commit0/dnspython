import base64
import enum
import struct
import dns.enum
import dns.exception
import dns.immutable
import dns.ipv4
import dns.ipv6
import dns.name
import dns.rdata
import dns.rdtypes.util
import dns.renderer
import dns.tokenizer
import dns.wire


class UnknownParamKey(dns.exception.DNSException):
    """Unknown SVCB ParamKey"""


class ParamKey(dns.enum.IntEnum):
    """SVCB ParamKey"""
    MANDATORY = 0
    ALPN = 1
    NO_DEFAULT_ALPN = 2
    PORT = 3
    IPV4HINT = 4
    ECH = 5
    IPV6HINT = 6
    DOHPATH = 7


class Emptiness(enum.IntEnum):
    NEVER = 0
    ALWAYS = 1
    ALLOWED = 2


_escaped = b'",\\'


@dns.immutable.immutable
class Param:
    """Abstract base class for SVCB parameters"""


@dns.immutable.immutable
class GenericParam(Param):
    """Generic SVCB parameter"""

    def __init__(self, value):
        self.value = dns.rdata.Rdata._as_bytes(value, True)


@dns.immutable.immutable
class MandatoryParam(Param):

    def __init__(self, keys):
        keys = sorted([_validate_key(key)[0] for key in keys])
        prior_k = None
        for k in keys:
            if k == prior_k:
                raise ValueError(f'duplicate key {k:d}')
            prior_k = k
            if k == ParamKey.MANDATORY:
                raise ValueError('listed the mandatory key as mandatory')
        self.keys = tuple(keys)


@dns.immutable.immutable
class ALPNParam(Param):

    def __init__(self, ids):
        self.ids = dns.rdata.Rdata._as_tuple(ids, lambda x: dns.rdata.Rdata
            ._as_bytes(x, True, 255, False))


@dns.immutable.immutable
class NoDefaultALPNParam(Param):
    pass


@dns.immutable.immutable
class PortParam(Param):

    def __init__(self, port):
        self.port = dns.rdata.Rdata._as_uint16(port)


@dns.immutable.immutable
class IPv4HintParam(Param):

    def __init__(self, addresses):
        self.addresses = dns.rdata.Rdata._as_tuple(addresses, dns.rdata.
            Rdata._as_ipv4_address)


@dns.immutable.immutable
class IPv6HintParam(Param):

    def __init__(self, addresses):
        self.addresses = dns.rdata.Rdata._as_tuple(addresses, dns.rdata.
            Rdata._as_ipv6_address)


@dns.immutable.immutable
class ECHParam(Param):

    def __init__(self, ech):
        self.ech = dns.rdata.Rdata._as_bytes(ech, True)


_class_for_key = {ParamKey.MANDATORY: MandatoryParam, ParamKey.ALPN:
    ALPNParam, ParamKey.NO_DEFAULT_ALPN: NoDefaultALPNParam, ParamKey.PORT:
    PortParam, ParamKey.IPV4HINT: IPv4HintParam, ParamKey.ECH: ECHParam,
    ParamKey.IPV6HINT: IPv6HintParam, ParamKey.DOHPATH: DOHPathParam}


@dns.immutable.immutable
class SVCBBase(dns.rdata.Rdata):
    """Base class for SVCB-like records"""
    __slots__ = ['priority', 'target', 'params']

    def __init__(self, rdclass, rdtype, priority, target, params):
        super().__init__(rdclass, rdtype)
        self.priority = self._as_uint16(priority)
        self.target = self._as_name(target)
        for k, v in params.items():
            k = ParamKey.make(k)
            if not isinstance(v, Param) and v is not None:
                raise ValueError(f'{k:d} not a Param')
        self.params = dns.immutable.Dict(params)
        mandatory = params.get(ParamKey.MANDATORY)
        if mandatory:
            for key in mandatory.keys:
                if key not in params:
                    raise ValueError(
                        f'key {key:d} declared mandatory but not present')
        if ParamKey.NO_DEFAULT_ALPN in params:
            if ParamKey.ALPN not in params:
                raise ValueError('no-default-alpn present, but alpn missing')
