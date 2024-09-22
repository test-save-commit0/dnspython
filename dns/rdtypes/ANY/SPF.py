import dns.immutable
import dns.rdtypes.txtbase


@dns.immutable.immutable
class SPF(dns.rdtypes.txtbase.TXTBase):
    """SPF record"""
