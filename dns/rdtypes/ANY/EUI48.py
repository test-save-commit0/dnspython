import dns.immutable
import dns.rdtypes.euibase


@dns.immutable.immutable
class EUI48(dns.rdtypes.euibase.EUIBase):
    """EUI48 record"""
    byte_len = 6
    text_len = byte_len * 3 - 1
