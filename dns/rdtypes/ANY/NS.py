import dns.immutable
import dns.rdtypes.nsbase


@dns.immutable.immutable
class NS(dns.rdtypes.nsbase.NSBase):
    """NS record"""
