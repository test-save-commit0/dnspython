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
    if not text:
        raise BadTTL("TTL cannot be empty")

    total_seconds = 0
    current_value = ""
    
    for char in text:
        if char.isdigit():
            current_value += char
        elif char.isalpha():
            if not current_value:
                raise BadTTL(f"Invalid TTL format: {text}")
            
            value = int(current_value)
            current_value = ""
            
            if char == 'w':
                total_seconds += value * 7 * 24 * 3600
            elif char == 'd':
                total_seconds += value * 24 * 3600
            elif char == 'h':
                total_seconds += value * 3600
            elif char == 'm':
                total_seconds += value * 60
            elif char == 's':
                total_seconds += value
            else:
                raise BadTTL(f"Invalid unit: {char}")
        else:
            raise BadTTL(f"Invalid character in TTL: {char}")
    
    if current_value:
        total_seconds += int(current_value)
    
    if total_seconds > MAX_TTL:
        raise BadTTL(f"TTL value {total_seconds} is greater than maximum allowed value {MAX_TTL}")
    
    return total_seconds
