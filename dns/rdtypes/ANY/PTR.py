import dns.immutable
import dns.rdtypes.nsbase


@dns.immutable.immutable
class PTR(dns.rdtypes.nsbase.NSBase):
    """PTR record"""
