import dns.immutable
import dns.rdtypes.nsbase


@dns.immutable.immutable
class DNAME(dns.rdtypes.nsbase.UncompressedNS):
    """DNAME record"""
