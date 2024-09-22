import dns.immutable
import dns.rdtypes.mxbase


@dns.immutable.immutable
class KX(dns.rdtypes.mxbase.UncompressedDowncasingMX):
    """KX record"""
