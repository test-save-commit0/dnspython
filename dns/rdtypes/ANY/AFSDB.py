import dns.immutable
import dns.rdtypes.mxbase


@dns.immutable.immutable
class AFSDB(dns.rdtypes.mxbase.UncompressedDowncasingMX):
    """AFSDB record"""

    @property
    def subtype(self):
        """the AFSDB subtype"""
        pass

    @property
    def hostname(self):
        """the AFSDB hostname"""
        pass
