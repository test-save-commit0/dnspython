"""DNS Reverse Map Names."""
import binascii
import dns.ipv4
import dns.ipv6
import dns.name
ipv4_reverse_domain = dns.name.from_text('in-addr.arpa.')
ipv6_reverse_domain = dns.name.from_text('ip6.arpa.')


def from_address(text: str, v4_origin: dns.name.Name=ipv4_reverse_domain,
    v6_origin: dns.name.Name=ipv6_reverse_domain) ->dns.name.Name:
    """Convert an IPv4 or IPv6 address in textual form into a Name object whose
    value is the reverse-map domain name of the address.

    *text*, a ``str``, is an IPv4 or IPv6 address in textual form
    (e.g. '127.0.0.1', '::1')

    *v4_origin*, a ``dns.name.Name`` to append to the labels corresponding to
    the address if the address is an IPv4 address, instead of the default
    (in-addr.arpa.)

    *v6_origin*, a ``dns.name.Name`` to append to the labels corresponding to
    the address if the address is an IPv6 address, instead of the default
    (ip6.arpa.)

    Raises ``dns.exception.SyntaxError`` if the address is badly formed.

    Returns a ``dns.name.Name``.
    """
    pass


def to_address(name: dns.name.Name, v4_origin: dns.name.Name=
    ipv4_reverse_domain, v6_origin: dns.name.Name=ipv6_reverse_domain) ->str:
    """Convert a reverse map domain name into textual address form.

    *name*, a ``dns.name.Name``, an IPv4 or IPv6 address in reverse-map name
    form.

    *v4_origin*, a ``dns.name.Name`` representing the top-level domain for
    IPv4 addresses, instead of the default (in-addr.arpa.)

    *v6_origin*, a ``dns.name.Name`` representing the top-level domain for
    IPv4 addresses, instead of the default (ip6.arpa.)

    Raises ``dns.exception.SyntaxError`` if the name does not have a
    reverse-map form.

    Returns a ``str``.
    """
    pass
