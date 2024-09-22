import dns.immutable
import dns.rdtypes.dsbase


@dns.immutable.immutable
class DS(dns.rdtypes.dsbase.DSBase):
    """DS record"""
