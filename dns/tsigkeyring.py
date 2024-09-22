"""A place to store TSIG keys."""
import base64
from typing import Any, Dict
import dns.name
import dns.tsig


def from_text(textring: Dict[str, Any]) ->Dict[dns.name.Name, dns.tsig.Key]:
    """Convert a dictionary containing (textual DNS name, base64 secret)
    pairs into a binary keyring which has (dns.name.Name, bytes) pairs, or
    a dictionary containing (textual DNS name, (algorithm, base64 secret))
    pairs into a binary keyring which has (dns.name.Name, dns.tsig.Key) pairs.
    @rtype: dict"""
    pass


def to_text(keyring: Dict[dns.name.Name, Any]) ->Dict[str, Any]:
    """Convert a dictionary containing (dns.name.Name, dns.tsig.Key) pairs
    into a text keyring which has (textual DNS name, (textual algorithm,
    base64 secret)) pairs, or a dictionary containing (dns.name.Name, bytes)
    pairs into a text keyring which has (textual DNS name, base64 secret) pairs.
    @rtype: dict"""
    pass
