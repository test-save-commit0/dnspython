import dns.immutable
import dns.rdtypes.mxbase


@dns.immutable.immutable
class MX(dns.rdtypes.mxbase.MXBase):
    """MX record"""
