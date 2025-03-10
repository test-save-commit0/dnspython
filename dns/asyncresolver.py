"""Asynchronous DNS stub resolver."""
import socket
import time
from typing import Any, Dict, List, Optional, Union
import dns._ddr
import dns.asyncbackend
import dns.asyncquery
import dns.exception
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
from dns.resolver import NXDOMAIN, NoAnswer, NoRootSOA, NotAbsolute
_udp = dns.asyncquery.udp
_tcp = dns.asyncquery.tcp


class Resolver(dns.resolver.BaseResolver):
    """Asynchronous DNS stub resolver."""

    async def resolve(self, qname: Union[dns.name.Name, str], rdtype: Union
        [dns.rdatatype.RdataType, str]=dns.rdatatype.A, rdclass: Union[dns.
        rdataclass.RdataClass, str]=dns.rdataclass.IN, tcp: bool=False,
        source: Optional[str]=None, raise_on_no_answer: bool=True,
        source_port: int=0, lifetime: Optional[float]=None, search:
        Optional[bool]=None, backend: Optional[dns.asyncbackend.Backend]=None
        ) ->dns.resolver.Answer:
        """Query nameservers asynchronously to find the answer to the question.

        *backend*, a ``dns.asyncbackend.Backend``, or ``None``.  If ``None``,
        the default, then dnspython will use the default backend.

        See :py:func:`dns.resolver.Resolver.resolve()` for the
        documentation of the other parameters, exceptions, and return
        type of this method.
        """
        if isinstance(qname, str):
            qname = dns.name.from_text(qname)
        if search is None:
            search = self.use_search_by_default
        if search:
            qname = self._ensure_absolute_name(qname)
        backend = self._get_backend(backend)
        request = dns.message.make_query(qname, rdtype, rdclass)
        answer = await self._resolve_with_cache(request, qname, rdtype, rdclass, tcp, source,
                                                raise_on_no_answer, source_port, lifetime, backend)
        return answer

    async def resolve_address(self, ipaddr: str, *args: Any, **kwargs: Any
        ) ->dns.resolver.Answer:
        """Use an asynchronous resolver to run a reverse query for PTR
        records.

        This utilizes the resolve() method to perform a PTR lookup on the
        specified IP address.

        *ipaddr*, a ``str``, the IPv4 or IPv6 address you want to get
        the PTR record for.

        All other arguments that can be passed to the resolve() function
        except for rdtype and rdclass are also supported by this
        function.

        """
        return await dns.asyncresolver.resolve(dns.reversename.from_address(ipaddr),
                                               rdtype='PTR',
                                               *args,
                                               **kwargs)

    async def resolve_name(self, name: Union[dns.name.Name, str], family:
        int=socket.AF_UNSPEC, **kwargs: Any) ->dns.resolver.HostAnswers:
        """Use an asynchronous resolver to query for address records.

        This utilizes the resolve() method to perform A and/or AAAA lookups on
        the specified name.

        *qname*, a ``dns.name.Name`` or ``str``, the name to resolve.

        *family*, an ``int``, the address family.  If socket.AF_UNSPEC
        (the default), both A and AAAA records will be retrieved.

        All other arguments that can be passed to the resolve() function
        except for rdtype and rdclass are also supported by this
        function.
        """
        rdtypes = []
        if family == socket.AF_INET6:
            rdtypes.append('AAAA')
        elif family == socket.AF_INET:
            rdtypes.append('A')
        else:
            rdtypes.extend(['A', 'AAAA'])

        answers = []
        for rdtype in rdtypes:
            try:
                answer = await self.resolve(name, rdtype, **kwargs)
                answers.append(answer)
            except dns.resolver.NoAnswer:
                pass

        if not answers:
            raise dns.resolver.NoAnswer

        return dns.resolver.HostAnswers(answers)

    async def canonical_name(self, name: Union[dns.name.Name, str]
        ) ->dns.name.Name:
        """Determine the canonical name of *name*.

        The canonical name is the name the resolver uses for queries
        after all CNAME and DNAME renamings have been applied.

        *name*, a ``dns.name.Name`` or ``str``, the query name.

        This method can raise any exception that ``resolve()`` can
        raise, other than ``dns.resolver.NoAnswer`` and
        ``dns.resolver.NXDOMAIN``.

        Returns a ``dns.name.Name``.
        """
        try:
            answer = await self.resolve(name, 'CNAME')
            cname = answer.canonical_name
        except dns.resolver.NoAnswer:
            cname = dns.name.from_text(name) if isinstance(name, str) else name
        return cname

    async def try_ddr(self, lifetime: float=5.0) ->None:
        """Try to update the resolver's nameservers using Discovery of Designated
        Resolvers (DDR).  If successful, the resolver will subsequently use
        DNS-over-HTTPS or DNS-over-TLS for future queries.

        *lifetime*, a float, is the maximum time to spend attempting DDR.  The default
        is 5 seconds.

        If the SVCB query is successful and results in a non-empty list of nameservers,
        then the resolver's nameservers are set to the returned servers in priority
        order.

        The current implementation does not use any address hints from the SVCB record,
        nor does it resolve addresses for the SCVB target name, rather it assumes that
        the bootstrap nameserver will always be one of the addresses and uses it.
        A future revision to the code may offer fuller support.  The code verifies that
        the bootstrap nameserver is in the Subject Alternative Name field of the
        TLS certficate.
        """
        try:
            ddr = dns._ddr.AsyncDDR(self)
            nameservers = await ddr.get_nameservers(lifetime)
            if nameservers:
                self.nameservers = nameservers
        except Exception:
            pass


default_resolver = None


def get_default_resolver() ->Resolver:
    """Get the default asynchronous resolver, initializing it if necessary."""
    global default_resolver
    if default_resolver is None:
        default_resolver = Resolver()
    return default_resolver


def reset_default_resolver() ->None:
    """Re-initialize default asynchronous resolver.

    Note that the resolver configuration (i.e. /etc/resolv.conf on UNIX
    systems) will be re-read immediately.
    """
    global default_resolver
    default_resolver = None


async def resolve(qname: Union[dns.name.Name, str], rdtype: Union[dns.
    rdatatype.RdataType, str]=dns.rdatatype.A, rdclass: Union[dns.
    rdataclass.RdataClass, str]=dns.rdataclass.IN, tcp: bool=False, source:
    Optional[str]=None, raise_on_no_answer: bool=True, source_port: int=0,
    lifetime: Optional[float]=None, search: Optional[bool]=None, backend:
    Optional[dns.asyncbackend.Backend]=None) ->dns.resolver.Answer:
    """Query nameservers asynchronously to find the answer to the question.

    This is a convenience function that uses the default resolver
    object to make the query.

    See :py:func:`dns.asyncresolver.Resolver.resolve` for more
    information on the parameters.
    """
    return await get_default_resolver().resolve(qname, rdtype, rdclass, tcp, source,
                                                raise_on_no_answer, source_port, lifetime,
                                                search, backend)


async def resolve_address(ipaddr: str, *args: Any, **kwargs: Any
    ) ->dns.resolver.Answer:
    """Use a resolver to run a reverse query for PTR records.

    See :py:func:`dns.asyncresolver.Resolver.resolve_address` for more
    information on the parameters.
    """
    return await get_default_resolver().resolve_address(ipaddr, *args, **kwargs)


async def resolve_name(name: Union[dns.name.Name, str], family: int=socket.
    AF_UNSPEC, **kwargs: Any) ->dns.resolver.HostAnswers:
    """Use a resolver to asynchronously query for address records.

    See :py:func:`dns.asyncresolver.Resolver.resolve_name` for more
    information on the parameters.
    """
    return await get_default_resolver().resolve_name(name, family, **kwargs)


async def canonical_name(name: Union[dns.name.Name, str]) ->dns.name.Name:
    """Determine the canonical name of *name*.

    See :py:func:`dns.resolver.Resolver.canonical_name` for more
    information on the parameters and possible exceptions.
    """
    return await get_default_resolver().canonical_name(name)


async def try_ddr(timeout: float=5.0) ->None:
    """Try to update the default resolver's nameservers using Discovery of Designated
    Resolvers (DDR).  If successful, the resolver will subsequently use
    DNS-over-HTTPS or DNS-over-TLS for future queries.

    See :py:func:`dns.resolver.Resolver.try_ddr` for more information.
    """
    await get_default_resolver().try_ddr(timeout)


async def zone_for_name(name: Union[dns.name.Name, str], rdclass: dns.
    rdataclass.RdataClass=dns.rdataclass.IN, tcp: bool=False, resolver:
    Optional[Resolver]=None, backend: Optional[dns.asyncbackend.Backend]=None
    ) ->dns.name.Name:
    """Find the name of the zone which contains the specified name.

    See :py:func:`dns.resolver.Resolver.zone_for_name` for more
    information on the parameters and possible exceptions.
    """
    if resolver is None:
        resolver = get_default_resolver()
    return await resolver.zone_for_name(name, rdclass, tcp, backend)


async def make_resolver_at(where: Union[dns.name.Name, str], port: int=53,
    family: int=socket.AF_UNSPEC, resolver: Optional[Resolver]=None
    ) ->Resolver:
    """Make a stub resolver using the specified destination as the full resolver.

    *where*, a ``dns.name.Name`` or ``str`` the domain name or IP address of the
    full resolver.

    *port*, an ``int``, the port to use.  If not specified, the default is 53.

    *family*, an ``int``, the address family to use.  This parameter is used if
    *where* is not an address.  The default is ``socket.AF_UNSPEC`` in which case
    the first address returned by ``resolve_name()`` will be used, otherwise the
    first address of the specified family will be used.

    *resolver*, a ``dns.asyncresolver.Resolver`` or ``None``, the resolver to use for
    resolution of hostnames.  If not specified, the default resolver will be used.

    Returns a ``dns.resolver.Resolver`` or raises an exception.
    """
    if resolver is None:
        resolver = get_default_resolver()
    
    if isinstance(where, str):
        where = dns.name.from_text(where)
    
    if isinstance(where, dns.name.Name):
        addresses = await resolver.resolve_name(where, family)
        address = addresses[0].address
    else:
        address = where
    
    r = Resolver()
    r.nameservers = [address]
    r.port = port
    return r


async def resolve_at(where: Union[dns.name.Name, str], qname: Union[dns.
    name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str]=dns.
    rdatatype.A, rdclass: Union[dns.rdataclass.RdataClass, str]=dns.
    rdataclass.IN, tcp: bool=False, source: Optional[str]=None,
    raise_on_no_answer: bool=True, source_port: int=0, lifetime: Optional[
    float]=None, search: Optional[bool]=None, backend: Optional[dns.
    asyncbackend.Backend]=None, port: int=53, family: int=socket.AF_UNSPEC,
    resolver: Optional[Resolver]=None) ->dns.resolver.Answer:
    """Query nameservers to find the answer to the question.

    This is a convenience function that calls ``dns.asyncresolver.make_resolver_at()``
    to make a resolver, and then uses it to resolve the query.

    See ``dns.asyncresolver.Resolver.resolve`` for more information on the resolution
    parameters, and ``dns.asyncresolver.make_resolver_at`` for information about the
    resolver parameters *where*, *port*, *family*, and *resolver*.

    If making more than one query, it is more efficient to call
    ``dns.asyncresolver.make_resolver_at()`` and then use that resolver for the queries
    instead of calling ``resolve_at()`` multiple times.
    """
    r = await make_resolver_at(where, port, family, resolver)
    return await r.resolve(qname, rdtype, rdclass, tcp, source, raise_on_no_answer,
                           source_port, lifetime, search, backend)
