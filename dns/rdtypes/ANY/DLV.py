import dns.immutable
import dns.rdtypes.dsbase


@dns.immutable.immutable
class DLV(dns.rdtypes.dsbase.DSBase):
    """DLV record"""
