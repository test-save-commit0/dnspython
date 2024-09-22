import dns.immutable
import dns.rdtypes.mxbase


@dns.immutable.immutable
class RT(dns.rdtypes.mxbase.UncompressedDowncasingMX):
    """RT record"""
