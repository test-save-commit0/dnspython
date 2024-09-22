import dns.immutable
import dns.rdtypes.txtbase


@dns.immutable.immutable
class TXT(dns.rdtypes.txtbase.TXTBase):
    """TXT record"""
