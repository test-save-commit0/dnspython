"""IPv4 helper functions."""
import struct
from typing import Union
import dns.exception


def inet_ntoa(address: bytes) ->str:
    """Convert an IPv4 address in binary form to text form.

    *address*, a ``bytes``, the IPv4 address in binary form.

    Returns a ``str``.
    """
    pass


def inet_aton(text: Union[str, bytes]) ->bytes:
    """Convert an IPv4 address in text form to binary form.

    *text*, a ``str`` or ``bytes``, the IPv4 address in textual form.

    Returns a ``bytes``.
    """
    pass


def canonicalize(text: Union[str, bytes]) ->str:
    """Verify that *address* is a valid text form IPv4 address and return its
    canonical text form.

    *text*, a ``str`` or ``bytes``, the IPv4 address in textual form.

    Raises ``dns.exception.SyntaxError`` if the text is not valid.
    """
    pass
