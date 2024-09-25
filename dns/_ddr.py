import socket
import ssl
import time
import asyncio
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
        if not hasattr(cert, 'get_subject_alt_name'):
            return False
        
        sans = cert.get_subject_alt_name()
        if sans is None:
            return False
        
        for san_type, san_value in sans:
            if san_type == 'DNS' and san_value == self.hostname:
                return True
            if san_type == 'IP Address' and san_value == self.bootstrap_address:
                return True
        
        return False


def _get_nameservers_sync(answer, lifetime):
    """Return a list of TLS-validated resolver nameservers extracted from an SVCB
    answer."""
    nameservers = []
    start_time = time.time()

    for rrset in answer.answer:
        for rr in rrset:
            if isinstance(rr, dns.rdtypes.svcbbase.SVCBBase):
                svcb_info = _SVCBInfo(
                    bootstrap_address=rr.target.to_text(),
                    port=rr.port,
                    hostname=rr.target.to_text(),
                    nameservers=[]
                )

                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((svcb_info.bootstrap_address, svcb_info.port), timeout=lifetime) as sock:
                        with context.wrap_socket(sock, server_hostname=svcb_info.hostname) as secure_sock:
                            cert = secure_sock.getpeercert()
                            if svcb_info.ddr_check_certificate(cert):
                                nameservers.append((svcb_info.bootstrap_address, svcb_info.port))
                except (socket.error, ssl.SSLError):
                    pass

            if time.time() - start_time > lifetime:
                break

        if time.time() - start_time > lifetime:
            break

    return nameservers


async def _get_nameservers_async(answer, lifetime):
    """Return a list of TLS-validated resolver nameservers extracted from an SVCB
    answer."""
    nameservers = []
    start_time = time.time()

    for rrset in answer.answer:
        for rr in rrset:
            if isinstance(rr, dns.rdtypes.svcbbase.SVCBBase):
                svcb_info = _SVCBInfo(
                    bootstrap_address=rr.target.to_text(),
                    port=rr.port,
                    hostname=rr.target.to_text(),
                    nameservers=[]
                )

                try:
                    context = ssl.create_default_context()
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(svcb_info.bootstrap_address, svcb_info.port),
                        timeout=lifetime
                    )
                    transport = writer.transport
                    protocol = transport.get_protocol()
                    ssl_context = await protocol._make_ssl_transport(
                        transport, protocol, context, svcb_info.hostname, server_side=False
                    )
                    cert = ssl_context.getpeercert()
                    if svcb_info.ddr_check_certificate(cert):
                        nameservers.append((svcb_info.bootstrap_address, svcb_info.port))
                    writer.close()
                    await writer.wait_closed()
                except (asyncio.TimeoutError, ssl.SSLError):
                    pass

            if time.time() - start_time > lifetime:
                break

        if time.time() - start_time > lifetime:
            break

    return nameservers
