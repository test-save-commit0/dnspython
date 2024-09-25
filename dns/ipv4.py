"""IPv4 helper functions."""
import struct
from typing import Union
import dns.exception


def inet_ntoa(address: bytes) ->str:
    """Convert an IPv4 address in binary form to text form.

    *address*, a ``bytes``, the IPv4 address in binary form.

    Returns a ``str``.
    """
    return '.'.join(str(b) for b in address)


def inet_aton(text: Union[str, bytes]) ->bytes:
    """Convert an IPv4 address in text form to binary form.

    *text*, a ``str`` or ``bytes``, the IPv4 address in textual form.

    Returns a ``bytes``.
    """
    if isinstance(text, bytes):
        text = text.decode()
    parts = text.split('.')
    if len(parts) != 4:
        raise dns.exception.SyntaxError("Invalid IPv4 address")
    try:
        return bytes(int(p) for p in parts)
    except ValueError:
        raise dns.exception.SyntaxError("Invalid IPv4 address")


def canonicalize(text: Union[str, bytes]) ->str:
    """Verify that *address* is a valid text form IPv4 address and return its
    canonical text form.

    *text*, a ``str`` or ``bytes``, the IPv4 address in textual form.

    Raises ``dns.exception.SyntaxError`` if the text is not valid.
    """
    try:
        binary = inet_aton(text)
        return inet_ntoa(binary)
    except dns.exception.SyntaxError:
        raise
