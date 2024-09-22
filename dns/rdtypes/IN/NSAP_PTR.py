import dns.immutable
import dns.rdtypes.nsbase


@dns.immutable.immutable
class NSAP_PTR(dns.rdtypes.nsbase.UncompressedNS):
    """NSAP-PTR record"""
