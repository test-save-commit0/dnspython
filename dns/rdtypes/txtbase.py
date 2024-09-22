"""TXT-like base class."""
from typing import Any, Dict, Iterable, Optional, Tuple, Union
import dns.exception
import dns.immutable
import dns.rdata
import dns.renderer
import dns.tokenizer


@dns.immutable.immutable
class TXTBase(dns.rdata.Rdata):
    """Base class for rdata that is like a TXT record (see RFC 1035)."""
    __slots__ = ['strings']

    def __init__(self, rdclass: dns.rdataclass.RdataClass, rdtype: dns.
        rdatatype.RdataType, strings: Iterable[Union[bytes, str]]):
        """Initialize a TXT-like rdata.

        *rdclass*, an ``int`` is the rdataclass of the Rdata.

        *rdtype*, an ``int`` is the rdatatype of the Rdata.

        *strings*, a tuple of ``bytes``
        """
        super().__init__(rdclass, rdtype)
        self.strings: Tuple[bytes] = self._as_tuple(strings, lambda x: self
            ._as_bytes(x, True, 255))
