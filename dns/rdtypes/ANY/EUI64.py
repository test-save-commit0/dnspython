import dns.immutable
import dns.rdtypes.euibase


@dns.immutable.immutable
class EUI64(dns.rdtypes.euibase.EUIBase):
    """EUI64 record"""
    byte_len = 8
    text_len = byte_len * 3 - 1
