import base64
import struct
import dns.exception
import dns.immutable
import dns.rcode
import dns.rdata


@dns.immutable.immutable
class TSIG(dns.rdata.Rdata):
    """TSIG record"""
    __slots__ = ['algorithm', 'time_signed', 'fudge', 'mac', 'original_id',
        'error', 'other']

    def __init__(self, rdclass, rdtype, algorithm, time_signed, fudge, mac,
        original_id, error, other):
        """Initialize a TSIG rdata.

        *rdclass*, an ``int`` is the rdataclass of the Rdata.

        *rdtype*, an ``int`` is the rdatatype of the Rdata.

        *algorithm*, a ``dns.name.Name``.

        *time_signed*, an ``int``.

        *fudge*, an ``int`.

        *mac*, a ``bytes``

        *original_id*, an ``int``

        *error*, an ``int``

        *other*, a ``bytes``
        """
        super().__init__(rdclass, rdtype)
        self.algorithm = self._as_name(algorithm)
        self.time_signed = self._as_uint48(time_signed)
        self.fudge = self._as_uint16(fudge)
        self.mac = self._as_bytes(mac)
        self.original_id = self._as_uint16(original_id)
        self.error = dns.rcode.Rcode.make(error)
        self.other = self._as_bytes(other)
