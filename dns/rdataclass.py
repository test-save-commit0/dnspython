"""DNS Rdata Classes."""
import dns.enum
import dns.exception


class RdataClass(dns.enum.IntEnum):
    """DNS Rdata Class"""
    RESERVED0 = 0
    IN = 1
    INTERNET = IN
    CH = 3
    CHAOS = CH
    HS = 4
    HESIOD = HS
    NONE = 254
    ANY = 255


_metaclasses = {RdataClass.NONE, RdataClass.ANY}


class UnknownRdataclass(dns.exception.DNSException):
    """A DNS class is unknown."""


def from_text(text: str) ->RdataClass:
    """Convert text into a DNS rdata class value.

    The input text can be a defined DNS RR class mnemonic or
    instance of the DNS generic class syntax.

    For example, "IN" and "CLASS1" will both result in a value of 1.

    Raises ``dns.rdatatype.UnknownRdataclass`` if the class is unknown.

    Raises ``ValueError`` if the rdata class value is not >= 0 and <= 65535.

    Returns a ``dns.rdataclass.RdataClass``.
    """
    pass


def to_text(value: RdataClass) ->str:
    """Convert a DNS rdata class value to text.

    If the value has a known mnemonic, it will be used, otherwise the
    DNS generic class syntax will be used.

    Raises ``ValueError`` if the rdata class value is not >= 0 and <= 65535.

    Returns a ``str``.
    """
    pass


def is_metaclass(rdclass: RdataClass) ->bool:
    """True if the specified class is a metaclass.

    The currently defined metaclasses are ANY and NONE.

    *rdclass* is a ``dns.rdataclass.RdataClass``.
    """
    pass


RESERVED0 = RdataClass.RESERVED0
IN = RdataClass.IN
INTERNET = RdataClass.INTERNET
CH = RdataClass.CH
CHAOS = RdataClass.CHAOS
HS = RdataClass.HS
HESIOD = RdataClass.HESIOD
NONE = RdataClass.NONE
ANY = RdataClass.ANY
