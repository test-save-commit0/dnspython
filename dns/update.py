"""DNS Dynamic Update Support"""
from typing import Any, List, Optional, Union
import dns.message
import dns.name
import dns.opcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.tsig


class UpdateSection(dns.enum.IntEnum):
    """Update sections"""
    ZONE = 0
    PREREQ = 1
    UPDATE = 2
    ADDITIONAL = 3


class UpdateMessage(dns.message.Message):
    _section_enum = UpdateSection

    def __init__(self, zone: Optional[Union[dns.name.Name, str]]=None,
        rdclass: dns.rdataclass.RdataClass=dns.rdataclass.IN, keyring:
        Optional[Any]=None, keyname: Optional[dns.name.Name]=None,
        keyalgorithm: Union[dns.name.Name, str]=dns.tsig.default_algorithm,
        id: Optional[int]=None):
        """Initialize a new DNS Update object.

        See the documentation of the Message class for a complete
        description of the keyring dictionary.

        *zone*, a ``dns.name.Name``, ``str``, or ``None``, the zone
        which is being updated.  ``None`` should only be used by dnspython's
        message constructors, as a zone is required for the convenience
        methods like ``add()``, ``replace()``, etc.

        *rdclass*, an ``int`` or ``str``, the class of the zone.

        The *keyring*, *keyname*, and *keyalgorithm* parameters are passed to
        ``use_tsig()``; see its documentation for details.
        """
        super().__init__(id=id)
        self.flags |= dns.opcode.to_flags(dns.opcode.UPDATE)
        if isinstance(zone, str):
            zone = dns.name.from_text(zone)
        self.origin = zone
        rdclass = dns.rdataclass.RdataClass.make(rdclass)
        self.zone_rdclass = rdclass
        if self.origin:
            self.find_rrset(self.zone, self.origin, rdclass, dns.rdatatype.
                SOA, create=True, force_unique=True)
        if keyring is not None:
            self.use_tsig(keyring, keyname, algorithm=keyalgorithm)

    @property
    def zone(self) ->List[dns.rrset.RRset]:
        """The zone section."""
        pass

    @property
    def prerequisite(self) ->List[dns.rrset.RRset]:
        """The prerequisite section."""
        pass

    @property
    def update(self) ->List[dns.rrset.RRset]:
        """The update section."""
        pass

    def _add_rr(self, name, ttl, rd, deleting=None, section=None):
        """Add a single RR to the update section."""
        pass

    def _add(self, replace, section, name, *args):
        """Add records.

        *replace* is the replacement mode.  If ``False``,
        RRs are added to an existing RRset; if ``True``, the RRset
        is replaced with the specified contents.  The second
        argument is the section to add to.  The third argument
        is always a name.  The other arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...
        """
        pass

    def add(self, name: Union[dns.name.Name, str], *args: Any) ->None:
        """Add records.

        The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...
        """
        pass

    def delete(self, name: Union[dns.name.Name, str], *args: Any) ->None:
        """Delete records.

        The first argument is always a name.  The other
        arguments can be:

                - *empty*

                - rdataset...

                - rdata...

                - rdtype, [string...]
        """
        pass

    def replace(self, name: Union[dns.name.Name, str], *args: Any) ->None:
        """Replace records.

        The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...

        Note that if you want to replace the entire node, you should do
        a delete of the name followed by one or more calls to add.
        """
        pass

    def present(self, name: Union[dns.name.Name, str], *args: Any) ->None:
        """Require that an owner name (and optionally an rdata type,
        or specific rdataset) exists as a prerequisite to the
        execution of the update.

        The first argument is always a name.
        The other arguments can be:

                - rdataset...

                - rdata...

                - rdtype, string...
        """
        pass

    def absent(self, name: Union[dns.name.Name, str], rdtype: Optional[
        Union[dns.rdatatype.RdataType, str]]=None) ->None:
        """Require that an owner name (and optionally an rdata type) does
        not exist as a prerequisite to the execution of the update."""
        pass


Update = UpdateMessage
ZONE = UpdateSection.ZONE
PREREQ = UpdateSection.PREREQ
UPDATE = UpdateSection.UPDATE
ADDITIONAL = UpdateSection.ADDITIONAL
