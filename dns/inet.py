"""Generic Internet address helper functions."""
import socket
from typing import Any, Optional, Tuple
import dns.ipv4
import dns.ipv6
AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6


def inet_pton(family: int, text: str) ->bytes:
    """Convert the textual form of a network address into its binary form.

    *family* is an ``int``, the address family.

    *text* is a ``str``, the textual address.

    Raises ``NotImplementedError`` if the address family specified is not
    implemented.

    Returns a ``bytes``.
    """
    pass


def inet_ntop(family: int, address: bytes) ->str:
    """Convert the binary form of a network address into its textual form.

    *family* is an ``int``, the address family.

    *address* is a ``bytes``, the network address in binary form.

    Raises ``NotImplementedError`` if the address family specified is not
    implemented.

    Returns a ``str``.
    """
    pass


def af_for_address(text: str) ->int:
    """Determine the address family of a textual-form network address.

    *text*, a ``str``, the textual address.

    Raises ``ValueError`` if the address family cannot be determined
    from the input.

    Returns an ``int``.
    """
    pass


def is_multicast(text: str) ->bool:
    """Is the textual-form network address a multicast address?

    *text*, a ``str``, the textual address.

    Raises ``ValueError`` if the address family cannot be determined
    from the input.

    Returns a ``bool``.
    """
    pass


def is_address(text: str) ->bool:
    """Is the specified string an IPv4 or IPv6 address?

    *text*, a ``str``, the textual address.

    Returns a ``bool``.
    """
    pass


def low_level_address_tuple(high_tuple: Tuple[str, int], af: Optional[int]=None
    ) ->Any:
    """Given a "high-level" address tuple, i.e.
    an (address, port) return the appropriate "low-level" address tuple
    suitable for use in socket calls.

    If an *af* other than ``None`` is provided, it is assumed the
    address in the high-level tuple is valid and has that af.  If af
    is ``None``, then af_for_address will be called.
    """
    pass


def any_for_af(af):
    """Return the 'any' address for the specified address family."""
    pass


def canonicalize(text: str) ->str:
    """Verify that *address* is a valid text form IPv4 or IPv6 address and return its
    canonical text form.  IPv6 addresses with scopes are rejected.

    *text*, a ``str``, the address in textual form.

    Raises ``ValueError`` if the text is not valid.
    """
    pass
