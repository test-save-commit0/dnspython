import socket
import time
from urllib.parse import urlparse
import dns.asyncbackend
import dns.inet
import dns.name
import dns.nameserver
import dns.query
import dns.rdtypes.svcbbase
_local_resolver_name = dns.name.from_text('_dns.resolver.arpa')


class _SVCBInfo:

    def __init__(self, bootstrap_address, port, hostname, nameservers):
        self.bootstrap_address = bootstrap_address
        self.port = port
        self.hostname = hostname
        self.nameservers = nameservers

    def ddr_check_certificate(self, cert):
        """Verify that the _SVCBInfo's address is in the cert's subjectAltName (SAN)"""
        pass


def _get_nameservers_sync(answer, lifetime):
    """Return a list of TLS-validated resolver nameservers extracted from an SVCB
    answer."""
    pass


async def _get_nameservers_async(answer, lifetime):
    """Return a list of TLS-validated resolver nameservers extracted from an SVCB
    answer."""
    pass
