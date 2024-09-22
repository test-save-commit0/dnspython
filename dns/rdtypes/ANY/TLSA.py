import dns.immutable
import dns.rdtypes.tlsabase


@dns.immutable.immutable
class TLSA(dns.rdtypes.tlsabase.TLSABase):
    """TLSA record"""
