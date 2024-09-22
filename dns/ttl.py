"""DNS TTL conversion."""
from typing import Union
import dns.exception
MAX_TTL = 2 ** 32 - 1


class BadTTL(dns.exception.SyntaxError):
    """DNS TTL value is not well-formed."""


def from_text(text: str) ->int:
    """Convert the text form of a TTL to an integer.

    The BIND 8 units syntax for TTLs (e.g. '1w6d4h3m10s') is supported.

    *text*, a ``str``, the textual TTL.

    Raises ``dns.ttl.BadTTL`` if the TTL is not well-formed.

    Returns an ``int``.
    """
    pass
