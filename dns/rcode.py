"""DNS Result Codes."""
from typing import Tuple
import dns.enum
import dns.exception


class Rcode(dns.enum.IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5
    YXDOMAIN = 6
    YXRRSET = 7
    NXRRSET = 8
    NOTAUTH = 9
    NOTZONE = 10
    DSOTYPENI = 11
    BADVERS = 16
    BADSIG = 16
    BADKEY = 17
    BADTIME = 18
    BADMODE = 19
    BADNAME = 20
    BADALG = 21
    BADTRUNC = 22
    BADCOOKIE = 23


class UnknownRcode(dns.exception.DNSException):
    """A DNS rcode is unknown."""


def from_text(text: str) ->Rcode:
    """Convert text into an rcode.

    *text*, a ``str``, the textual rcode or an integer in textual form.

    Raises ``dns.rcode.UnknownRcode`` if the rcode mnemonic is unknown.

    Returns a ``dns.rcode.Rcode``.
    """
    try:
        return Rcode[text.upper()]
    except KeyError:
        try:
            value = int(text)
            return Rcode(value)
        except (ValueError, KeyError):
            raise UnknownRcode(f"Unknown rcode mnemonic: {text}")


def from_flags(flags: int, ednsflags: int) ->Rcode:
    """Return the rcode value encoded by flags and ednsflags.

    *flags*, an ``int``, the DNS flags field.

    *ednsflags*, an ``int``, the EDNS flags field.

    Raises ``ValueError`` if rcode is < 0 or > 4095

    Returns a ``dns.rcode.Rcode``.
    """
    rcode = (flags & 0x000f) | ((ednsflags & 0xff0000) >> 4)
    if rcode < 0 or rcode > 4095:
        raise ValueError(f"rcode {rcode} is out of range")
    return Rcode(rcode)


def to_flags(value: Rcode) ->Tuple[int, int]:
    """Return a (flags, ednsflags) tuple which encodes the rcode.

    *value*, a ``dns.rcode.Rcode``, the rcode.

    Raises ``ValueError`` if rcode is < 0 or > 4095.

    Returns an ``(int, int)`` tuple.
    """
    if value < 0 or value > 4095:
        raise ValueError(f"rcode {value} is out of range")
    flags = value & 0x000f
    ednsflags = (value & 0xff0) << 4
    return (flags, ednsflags)


def to_text(value: Rcode, tsig: bool=False) ->str:
    """Convert rcode into text.

    *value*, a ``dns.rcode.Rcode``, the rcode.

    Raises ``ValueError`` if rcode is < 0 or > 4095.

    Returns a ``str``.
    """
    if value < 0 or value > 4095:
        raise ValueError(f"rcode {value} is out of range")
    try:
        return Rcode(value).name
    except ValueError:
        return str(value)


NOERROR = Rcode.NOERROR
FORMERR = Rcode.FORMERR
SERVFAIL = Rcode.SERVFAIL
NXDOMAIN = Rcode.NXDOMAIN
NOTIMP = Rcode.NOTIMP
REFUSED = Rcode.REFUSED
YXDOMAIN = Rcode.YXDOMAIN
YXRRSET = Rcode.YXRRSET
NXRRSET = Rcode.NXRRSET
NOTAUTH = Rcode.NOTAUTH
NOTZONE = Rcode.NOTZONE
DSOTYPENI = Rcode.DSOTYPENI
BADVERS = Rcode.BADVERS
BADSIG = Rcode.BADSIG
BADKEY = Rcode.BADKEY
BADTIME = Rcode.BADTIME
BADMODE = Rcode.BADMODE
BADNAME = Rcode.BADNAME
BADALG = Rcode.BADALG
BADTRUNC = Rcode.BADTRUNC
BADCOOKIE = Rcode.BADCOOKIE
