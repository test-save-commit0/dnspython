"""IPv6 helper functions."""
import binascii
import re
from typing import List, Union
import dns.exception
import dns.ipv4
_leading_zero = re.compile('0+([0-9a-f]+)')


def inet_ntoa(address: bytes) ->str:
    """Convert an IPv6 address in binary form to text form.

    *address*, a ``bytes``, the IPv6 address in binary form.

    Raises ``ValueError`` if the address isn't 16 bytes long.
    Returns a ``str``.
    """
    pass


_v4_ending = re.compile(b'(.*):(\\d+\\.\\d+\\.\\d+\\.\\d+)$')
_colon_colon_start = re.compile(b'::.*')
_colon_colon_end = re.compile(b'.*::$')


def inet_aton(text: Union[str, bytes], ignore_scope: bool=False) ->bytes:
    """Convert an IPv6 address in text form to binary form.

    *text*, a ``str`` or ``bytes``, the IPv6 address in textual form.

    *ignore_scope*, a ``bool``.  If ``True``, a scope will be ignored.
    If ``False``, the default, it is an error for a scope to be present.

    Returns a ``bytes``.
    """
    pass


_mapped_prefix = b'\x00' * 10 + b'\xff\xff'


def is_mapped(address: bytes) ->bool:
    """Is the specified address a mapped IPv4 address?

    *address*, a ``bytes`` is an IPv6 address in binary form.

    Returns a ``bool``.
    """
    pass


def canonicalize(text: Union[str, bytes]) ->str:
    """Verify that *address* is a valid text form IPv6 address and return its
    canonical text form.  Addresses with scopes are rejected.

    *text*, a ``str`` or ``bytes``, the IPv6 address in textual form.

    Raises ``dns.exception.SyntaxError`` if the text is not valid.
    """
    pass
