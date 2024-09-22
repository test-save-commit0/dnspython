import dns.immutable
import dns.rdtypes.dsbase


@dns.immutable.immutable
class CDS(dns.rdtypes.dsbase.DSBase):
    """CDS record"""
    _digest_length_by_type = {**dns.rdtypes.dsbase.DSBase.
        _digest_length_by_type, (0): 1}
