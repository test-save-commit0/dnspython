"""DNS Zones."""
import re
import sys
from typing import Any, Iterable, List, Optional, Set, Tuple, Union
import dns.exception
import dns.grange
import dns.name
import dns.node
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.tokenizer
import dns.transaction
import dns.ttl


class UnknownOrigin(dns.exception.DNSException):
    """Unknown origin"""


class CNAMEAndOtherData(dns.exception.DNSException):
    """A node has a CNAME and other data"""


SavedStateType = Tuple[dns.tokenizer.Tokenizer, Optional[dns.name.Name],
    Optional[dns.name.Name], Optional[Any], int, bool, int, bool]


class Reader:
    """Read a DNS zone file into a transaction."""

    def __init__(self, tok: dns.tokenizer.Tokenizer, rdclass: dns.
        rdataclass.RdataClass, txn: dns.transaction.Transaction,
        allow_include: bool=False, allow_directives: Union[bool, Iterable[
        str]]=True, force_name: Optional[dns.name.Name]=None, force_ttl:
        Optional[int]=None, force_rdclass: Optional[dns.rdataclass.
        RdataClass]=None, force_rdtype: Optional[dns.rdatatype.RdataType]=
        None, default_ttl: Optional[int]=None):
        self.tok = tok
        self.zone_origin, self.relativize, _ = txn.manager.origin_information()
        self.current_origin = self.zone_origin
        self.last_ttl = 0
        self.last_ttl_known = False
        if force_ttl is not None:
            default_ttl = force_ttl
        if default_ttl is None:
            self.default_ttl = 0
            self.default_ttl_known = False
        else:
            self.default_ttl = default_ttl
            self.default_ttl_known = True
        self.last_name = self.current_origin
        self.zone_rdclass = rdclass
        self.txn = txn
        self.saved_state: List[SavedStateType] = []
        self.current_file: Optional[Any] = None
        self.allowed_directives: Set[str]
        if allow_directives is True:
            self.allowed_directives = {'$GENERATE', '$ORIGIN', '$TTL'}
            if allow_include:
                self.allowed_directives.add('$INCLUDE')
        elif allow_directives is False:
            self.allowed_directives = set()
        else:
            self.allowed_directives = set(_upper_dollarize(d) for d in
                allow_directives)
        self.force_name = force_name
        self.force_ttl = force_ttl
        self.force_rdclass = force_rdclass
        self.force_rdtype = force_rdtype
        self.txn.check_put_rdataset(_check_cname_and_other_data)

    def _rr_line(self):
        """Process one line from a DNS zone file."""
        token = self.tok.get()
        if token.is_whitespace():
            token = self.tok.get()
        if token.is_eol():
            return
        self.tok.unget(token)
        
        (name, ttl, rdclass, rdtype, covers) = self.tok.get_rr_header()
        if self.force_name is not None:
            name = self.force_name
        if self.force_ttl is not None:
            ttl = self.force_ttl
        if self.force_rdclass is not None:
            rdclass = self.force_rdclass
        if self.force_rdtype is not None:
            rdtype = self.force_rdtype
        
        if name is None:
            name = self.last_name
        else:
            self.last_name = name
        if ttl is None:
            ttl = self.last_ttl
            if ttl is None:
                ttl = self.default_ttl
        else:
            self.last_ttl = ttl
        if rdclass is None:
            rdclass = self.zone_rdclass
        
        token = self.tok.get()
        if not token.is_identifier():
            raise dns.exception.SyntaxError
        
        rd = dns.rdata.from_text(rdclass, rdtype, token.value,
                                 origin=self.current_origin,
                                 relativize=self.relativize)
        self.txn.add(name, ttl, rd)

    def _generate_line(self):
        """Process one line containing the GENERATE statement from a DNS
        zone file."""
        token = self.tok.get()
        if not token.is_identifier() or token.value != '$GENERATE':
            raise dns.exception.SyntaxError

        start = self.tok.get().value
        stop = self.tok.get().value
        step = self.tok.get().value
        pattern = self.tok.get().value
        ttl = self.default_ttl
        rdclass = self.zone_rdclass
        rdtype = None
        covers = dns.rdatatype.NONE

        token = self.tok.get()
        if token.is_identifier():
            rdtype = dns.rdatatype.from_text(token.value)
            token = self.tok.get()
            if token.is_identifier():
                covers = dns.rdatatype.from_text(token.value)
        
        if not token.is_eol_or_eof():
            raise dns.exception.SyntaxError

        for i in dns.grange.from_text(start, stop, step):
            name = pattern.replace('$', str(i))
            name = dns.name.from_text(name, self.current_origin)
            rdata = pattern.replace('$', str(i))
            rd = dns.rdata.from_text(rdclass, rdtype, rdata,
                                     origin=self.current_origin,
                                     relativize=self.relativize)
            self.txn.add(name, ttl, rd)

    def read(self) ->None:
        """Read a DNS zone file and build a zone object.

        @raises dns.zone.NoSOA: No SOA RR was found at the zone origin
        @raises dns.zone.NoNS: No NS RRset was found at the zone origin
        """
        try:
            while True:
                token = self.tok.get(True, True)
                if token.is_eof():
                    break
                if token.is_eol():
                    continue
                self.tok.unget(token)
                if token.value == '$GENERATE':
                    self._generate_line()
                elif token.value.startswith('$'):
                    self._directive_line()
                else:
                    self._rr_line()
        except dns.exception.SyntaxError:
            raise
        except Exception as e:
            raise dns.exception.SyntaxError(f"error reading zone: {e}")

        # Check if SOA and NS records exist at the zone origin
        has_soa = False
        has_ns = False
        for (name, rdataset) in self.txn._iterate_rdatasets():
            if name == self.zone_origin:
                if rdataset.rdtype == dns.rdatatype.SOA:
                    has_soa = True
                elif rdataset.rdtype == dns.rdatatype.NS:
                    has_ns = True
            if has_soa and has_ns:
                break

        if not has_soa:
            raise dns.zone.NoSOA
        if not has_ns:
            raise dns.zone.NoNS


class RRsetsReaderTransaction(dns.transaction.Transaction):

    def __init__(self, manager, replacement, read_only):
        assert not read_only
        super().__init__(manager, replacement, read_only)
        self.rdatasets = {}


class RRSetsReaderManager(dns.transaction.TransactionManager):

    def __init__(self, origin=dns.name.root, relativize=False, rdclass=dns.
        rdataclass.IN):
        self.origin = origin
        self.relativize = relativize
        self.rdclass = rdclass
        self.rrsets = []


def read_rrsets(text: Any, name: Optional[Union[dns.name.Name, str]]=None,
    ttl: Optional[int]=None, rdclass: Optional[Union[dns.rdataclass.
    RdataClass, str]]=dns.rdataclass.IN, default_rdclass: Union[dns.
    rdataclass.RdataClass, str]=dns.rdataclass.IN, rdtype: Optional[Union[
    dns.rdatatype.RdataType, str]]=None, default_ttl: Optional[Union[int,
    str]]=None, idna_codec: Optional[dns.name.IDNACodec]=None, origin:
    Optional[Union[dns.name.Name, str]]=dns.name.root, relativize: bool=False
    ) ->List[dns.rrset.RRset]:
    """Read one or more rrsets from the specified text, possibly subject
    to restrictions.

    *text*, a file object or a string, is the input to process.

    *name*, a string, ``dns.name.Name``, or ``None``, is the owner name of
    the rrset.  If not ``None``, then the owner name is "forced", and the
    input must not specify an owner name.  If ``None``, then any owner names
    are allowed and must be present in the input.

    *ttl*, an ``int``, string, or None.  If not ``None``, the the TTL is
    forced to be the specified value and the input must not specify a TTL.
    If ``None``, then a TTL may be specified in the input.  If it is not
    specified, then the *default_ttl* will be used.

    *rdclass*, a ``dns.rdataclass.RdataClass``, string, or ``None``.  If
    not ``None``, then the class is forced to the specified value, and the
    input must not specify a class.  If ``None``, then the input may specify
    a class that matches *default_rdclass*.  Note that it is not possible to
    return rrsets with differing classes; specifying ``None`` for the class
    simply allows the user to optionally type a class as that may be convenient
    when cutting and pasting.

    *default_rdclass*, a ``dns.rdataclass.RdataClass`` or string.  The class
    of the returned rrsets.

    *rdtype*, a ``dns.rdatatype.RdataType``, string, or ``None``.  If not
    ``None``, then the type is forced to the specified value, and the
    input must not specify a type.  If ``None``, then a type must be present
    for each RR.

    *default_ttl*, an ``int``, string, or ``None``.  If not ``None``, then if
    the TTL is not forced and is not specified, then this value will be used.
    if ``None``, then if the TTL is not forced an error will occur if the TTL
    is not specified.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.  Note that codecs only apply to the owner name; dnspython does
    not do IDNA for names in rdata, as there is no IDNA zonefile format.

    *origin*, a string, ``dns.name.Name``, or ``None``, is the origin for any
    relative names in the input, and also the origin to relativize to if
    *relativize* is ``True``.

    *relativize*, a bool.  If ``True``, names are relativized to the *origin*;
    if ``False`` then any relative names in the input are made absolute by
    appending the *origin*.
    """
    if isinstance(text, str):
        text = StringIO(text)
    
    tok = dns.tokenizer.Tokenizer(text, filename='<string>')
    
    if isinstance(origin, str):
        origin = dns.name.from_text(origin, dns.name.root)
    
    if isinstance(default_rdclass, str):
        default_rdclass = dns.rdataclass.from_text(default_rdclass)
    
    if isinstance(rdclass, str):
        rdclass = dns.rdataclass.from_text(rdclass)
    elif rdclass is None:
        rdclass = default_rdclass
    
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)
    
    if isinstance(ttl, str):
        ttl = dns.ttl.from_text(ttl)
    
    if isinstance(default_ttl, str):
        default_ttl = dns.ttl.from_text(default_ttl)
    
    manager = RRSetsReaderManager(origin, relativize, rdclass)
    with manager.transaction(True) as txn:
        reader = Reader(tok, rdclass, txn, allow_include=False,
                        allow_directives=False, force_name=name,
                        force_ttl=ttl, force_rdclass=rdclass,
                        force_rdtype=rdtype, default_ttl=default_ttl)
        reader.read()
    
    return manager.rrsets
