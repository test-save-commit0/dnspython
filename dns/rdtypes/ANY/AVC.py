import dns.immutable
import dns.rdtypes.txtbase


@dns.immutable.immutable
class AVC(dns.rdtypes.txtbase.TXTBase):
    """AVC record"""
