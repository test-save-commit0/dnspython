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
    keyring = {}
    for name, value in textring.items():
        key_name = dns.name.from_text(name)
        if isinstance(value, str):
            # Case 1: (textual DNS name, base64 secret)
            secret = base64.b64decode(value)
            keyring[key_name] = secret
        elif isinstance(value, tuple) and len(value) == 2:
            # Case 2: (textual DNS name, (algorithm, base64 secret))
            algorithm, secret = value
            key = dns.tsig.Key(algorithm, base64.b64decode(secret))
            keyring[key_name] = key
        else:
            raise ValueError(f"Invalid value for key {name}")
    return keyring


def to_text(keyring: Dict[dns.name.Name, Any]) ->Dict[str, Any]:
    """Convert a dictionary containing (dns.name.Name, dns.tsig.Key) pairs
    into a text keyring which has (textual DNS name, (textual algorithm,
    base64 secret)) pairs, or a dictionary containing (dns.name.Name, bytes)
    pairs into a text keyring which has (textual DNS name, base64 secret) pairs.
    @rtype: dict"""
    textring = {}
    for name, value in keyring.items():
        text_name = name.to_text()
        if isinstance(value, bytes):
            # Case 1: (dns.name.Name, bytes)
            textring[text_name] = base64.b64encode(value).decode('ascii')
        elif isinstance(value, dns.tsig.Key):
            # Case 2: (dns.name.Name, dns.tsig.Key)
            algorithm = value.algorithm
            secret = base64.b64encode(value.secret).decode('ascii')
            textring[text_name] = (algorithm, secret)
        else:
            raise ValueError(f"Invalid value for key {name}")
    return textring
