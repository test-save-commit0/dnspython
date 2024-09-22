import dns.immutable
import dns.rdtypes.dnskeybase
from dns.rdtypes.dnskeybase import REVOKE, SEP, ZONE


@dns.immutable.immutable
class DNSKEY(dns.rdtypes.dnskeybase.DNSKEYBase):
    """DNSKEY record"""
