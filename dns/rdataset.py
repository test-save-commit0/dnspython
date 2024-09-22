"""DNS rdatasets (an rdataset is a set of rdatas of a given type and class)"""
import io
import random
import struct
from typing import Any, Collection, Dict, List, Optional, Union, cast
import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.renderer
import dns.set
import dns.ttl
SimpleSet = dns.set.Set


class DifferingCovers(dns.exception.DNSException):
    """An attempt was made to add a DNS SIG/RRSIG whose covered type
    is not the same as that of the other rdatas in the rdataset."""


class IncompatibleTypes(dns.exception.DNSException):
    """An attempt was made to add DNS RR data of an incompatible type."""


class Rdataset(dns.set.Set):
    """A DNS rdataset."""
    __slots__ = ['rdclass', 'rdtype', 'covers', 'ttl']

    def __init__(self, rdclass: dns.rdataclass.RdataClass, rdtype: dns.
        rdatatype.RdataType, covers: dns.rdatatype.RdataType=dns.rdatatype.
        NONE, ttl: int=0):
        """Create a new rdataset of the specified class and type.

        *rdclass*, a ``dns.rdataclass.RdataClass``, the rdataclass.

        *rdtype*, an ``dns.rdatatype.RdataType``, the rdatatype.

        *covers*, an ``dns.rdatatype.RdataType``, the covered rdatatype.

        *ttl*, an ``int``, the TTL.
        """
        super().__init__()
        self.rdclass = rdclass
        self.rdtype: dns.rdatatype.RdataType = rdtype
        self.covers: dns.rdatatype.RdataType = covers
        self.ttl = ttl

    def update_ttl(self, ttl: int) ->None:
        """Perform TTL minimization.

        Set the TTL of the rdataset to be the lesser of the set's current
        TTL or the specified TTL.  If the set contains no rdatas, set the TTL
        to the specified TTL.

        *ttl*, an ``int`` or ``str``.
        """
        pass

    def add(self, rd: dns.rdata.Rdata, ttl: Optional[int]=None) ->None:
        """Add the specified rdata to the rdataset.

        If the optional *ttl* parameter is supplied, then
        ``self.update_ttl(ttl)`` will be called prior to adding the rdata.

        *rd*, a ``dns.rdata.Rdata``, the rdata

        *ttl*, an ``int``, the TTL.

        Raises ``dns.rdataset.IncompatibleTypes`` if the type and class
        do not match the type and class of the rdataset.

        Raises ``dns.rdataset.DifferingCovers`` if the type is a signature
        type and the covered type does not match that of the rdataset.
        """
        pass

    def update(self, other):
        """Add all rdatas in other to self.

        *other*, a ``dns.rdataset.Rdataset``, the rdataset from which
        to update.
        """
        pass

    def __repr__(self):
        if self.covers == 0:
            ctext = ''
        else:
            ctext = '(' + dns.rdatatype.to_text(self.covers) + ')'
        return '<DNS ' + dns.rdataclass.to_text(self.rdclass
            ) + ' ' + dns.rdatatype.to_text(self.rdtype
            ) + ctext + ' rdataset: ' + self._rdata_repr() + '>'

    def __str__(self):
        return self.to_text()

    def __eq__(self, other):
        if not isinstance(other, Rdataset):
            return False
        if (self.rdclass != other.rdclass or self.rdtype != other.rdtype or
            self.covers != other.covers):
            return False
        return super().__eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_text(self, name: Optional[dns.name.Name]=None, origin: Optional[
        dns.name.Name]=None, relativize: bool=True, override_rdclass:
        Optional[dns.rdataclass.RdataClass]=None, want_comments: bool=False,
        **kw: Dict[str, Any]) ->str:
        """Convert the rdataset into DNS zone file format.

        See ``dns.name.Name.choose_relativity`` for more information
        on how *origin* and *relativize* determine the way names
        are emitted.

        Any additional keyword arguments are passed on to the rdata
        ``to_text()`` method.

        *name*, a ``dns.name.Name``.  If name is not ``None``, emit RRs with
        *name* as the owner name.

        *origin*, a ``dns.name.Name`` or ``None``, the origin for relative
        names.

        *relativize*, a ``bool``.  If ``True``, names will be relativized
        to *origin*.

        *override_rdclass*, a ``dns.rdataclass.RdataClass`` or ``None``.
        If not ``None``, use this class instead of the Rdataset's class.

        *want_comments*, a ``bool``.  If ``True``, emit comments for rdata
        which have them.  The default is ``False``.
        """
        pass

    def to_wire(self, name: dns.name.Name, file: Any, compress: Optional[
        dns.name.CompressType]=None, origin: Optional[dns.name.Name]=None,
        override_rdclass: Optional[dns.rdataclass.RdataClass]=None,
        want_shuffle: bool=True) ->int:
        """Convert the rdataset to wire format.

        *name*, a ``dns.name.Name`` is the owner name to use.

        *file* is the file where the name is emitted (typically a
        BytesIO file).

        *compress*, a ``dict``, is the compression table to use.  If
        ``None`` (the default), names will not be compressed.

        *origin* is a ``dns.name.Name`` or ``None``.  If the name is
        relative and origin is not ``None``, then *origin* will be appended
        to it.

        *override_rdclass*, an ``int``, is used as the class instead of the
        class of the rdataset.  This is useful when rendering rdatasets
        associated with dynamic updates.

        *want_shuffle*, a ``bool``.  If ``True``, then the order of the
        Rdatas within the Rdataset will be shuffled before rendering.

        Returns an ``int``, the number of records emitted.
        """
        pass

    def match(self, rdclass: dns.rdataclass.RdataClass, rdtype: dns.
        rdatatype.RdataType, covers: dns.rdatatype.RdataType) ->bool:
        """Returns ``True`` if this rdataset matches the specified class,
        type, and covers.
        """
        pass

    def processing_order(self) ->List[dns.rdata.Rdata]:
        """Return rdatas in a valid processing order according to the type's
        specification.  For example, MX records are in preference order from
        lowest to highest preferences, with items of the same preference
        shuffled.

        For types that do not define a processing order, the rdatas are
        simply shuffled.
        """
        pass


@dns.immutable.immutable
class ImmutableRdataset(Rdataset):
    """An immutable DNS rdataset."""
    _clone_class = Rdataset

    def __init__(self, rdataset: Rdataset):
        """Create an immutable rdataset from the specified rdataset."""
        super().__init__(rdataset.rdclass, rdataset.rdtype, rdataset.covers,
            rdataset.ttl)
        self.items = dns.immutable.Dict(rdataset.items)

    def __delitem__(self, i):
        raise TypeError('immutable')

    def __ior__(self, other):
        raise TypeError('immutable')

    def __iand__(self, other):
        raise TypeError('immutable')

    def __iadd__(self, other):
        raise TypeError('immutable')

    def __isub__(self, other):
        raise TypeError('immutable')

    def __copy__(self):
        return ImmutableRdataset(super().copy())


def from_text_list(rdclass: Union[dns.rdataclass.RdataClass, str], rdtype:
    Union[dns.rdatatype.RdataType, str], ttl: int, text_rdatas: Collection[
    str], idna_codec: Optional[dns.name.IDNACodec]=None, origin: Optional[
    dns.name.Name]=None, relativize: bool=True, relativize_to: Optional[dns
    .name.Name]=None) ->Rdataset:
    """Create an rdataset with the specified class, type, and TTL, and with
    the specified list of rdatas in text format.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder to use; if ``None``, the default IDNA 2003
    encoder/decoder is used.

    *origin*, a ``dns.name.Name`` (or ``None``), the
    origin to use for relative names.

    *relativize*, a ``bool``.  If true, name will be relativized.

    *relativize_to*, a ``dns.name.Name`` (or ``None``), the origin to use
    when relativizing names.  If not set, the *origin* value will be used.

    Returns a ``dns.rdataset.Rdataset`` object.
    """
    pass


def from_text(rdclass: Union[dns.rdataclass.RdataClass, str], rdtype: Union
    [dns.rdatatype.RdataType, str], ttl: int, *text_rdatas: Any) ->Rdataset:
    """Create an rdataset with the specified class, type, and TTL, and with
    the specified rdatas in text format.

    Returns a ``dns.rdataset.Rdataset`` object.
    """
    pass


def from_rdata_list(ttl: int, rdatas: Collection[dns.rdata.Rdata]) ->Rdataset:
    """Create an rdataset with the specified TTL, and with
    the specified list of rdata objects.

    Returns a ``dns.rdataset.Rdataset`` object.
    """
    pass


def from_rdata(ttl: int, *rdatas: Any) ->Rdataset:
    """Create an rdataset with the specified TTL, and with
    the specified rdata objects.

    Returns a ``dns.rdataset.Rdataset`` object.
    """
    pass
