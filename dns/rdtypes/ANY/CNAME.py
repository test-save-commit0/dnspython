import dns.immutable
import dns.rdtypes.nsbase


@dns.immutable.immutable
class CNAME(dns.rdtypes.nsbase.NSBase):
    """CNAME record

    Note: although CNAME is officially a singleton type, dnspython allows
    non-singleton CNAME rdatasets because such sets have been commonly
    used by BIND and other nameservers for load balancing."""
