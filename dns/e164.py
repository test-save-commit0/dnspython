"""DNS E.164 helpers."""
from typing import Iterable, Optional, Union
import dns.exception
import dns.name
import dns.resolver
public_enum_domain = dns.name.from_text('e164.arpa.')


def from_e164(text: str, origin: Optional[dns.name.Name]=public_enum_domain
    ) ->dns.name.Name:
    """Convert an E.164 number in textual form into a Name object whose
    value is the ENUM domain name for that number.

    Non-digits in the text are ignored, i.e. "16505551212",
    "+1.650.555.1212" and "1 (650) 555-1212" are all the same.

    *text*, a ``str``, is an E.164 number in textual form.

    *origin*, a ``dns.name.Name``, the domain in which the number
    should be constructed.  The default is ``e164.arpa.``.

    Returns a ``dns.name.Name``.
    """
    digits = ''.join(filter(str.isdigit, text))
    if not digits:
        raise dns.exception.SyntaxError("No digits found in E.164 number")
    
    labels = list(reversed(digits))
    name = dns.name.Name(labels)
    
    if origin is not None:
        name = name.derelativize(origin)
    
    return name


def to_e164(name: dns.name.Name, origin: Optional[dns.name.Name]=
    public_enum_domain, want_plus_prefix: bool=True) ->str:
    """Convert an ENUM domain name into an E.164 number.

    Note that dnspython does not have any information about preferred
    number formats within national numbering plans, so all numbers are
    emitted as a simple string of digits, prefixed by a '+' (unless
    *want_plus_prefix* is ``False``).

    *name* is a ``dns.name.Name``, the ENUM domain name.

    *origin* is a ``dns.name.Name``, a domain containing the ENUM
    domain name.  The name is relativized to this domain before being
    converted to text.  If ``None``, no relativization is done.

    *want_plus_prefix* is a ``bool``.  If True, add a '+' to the beginning of
    the returned number.

    Returns a ``str``.

    """
    if origin is not None:
        name = name.relativize(origin)
    
    digits = ''.join(reversed(name.labels))
    
    if want_plus_prefix:
        return '+' + digits
    else:
        return digits


def query(number: str, domains: Iterable[Union[dns.name.Name, str]],
    resolver: Optional[dns.resolver.Resolver]=None) ->dns.resolver.Answer:
    """Look for NAPTR RRs for the specified number in the specified domains.

    e.g. lookup('16505551212', ['e164.dnspython.org.', 'e164.arpa.'])

    *number*, a ``str`` is the number to look for.

    *domains* is an iterable containing ``dns.name.Name`` values.

    *resolver*, a ``dns.resolver.Resolver``, is the resolver to use.  If
    ``None``, the default resolver is used.
    """
    if resolver is None:
        resolver = dns.resolver.get_default_resolver()
    
    for domain in domains:
        if isinstance(domain, str):
            domain = dns.name.from_text(domain)
        
        e164_name = from_e164(number, domain)
        
        try:
            answer = resolver.resolve(e164_name, 'NAPTR')
            return answer
        except dns.resolver.NXDOMAIN:
            continue
    
    raise dns.resolver.NXDOMAIN(f"No NAPTR records found for {number} in the specified domains")
