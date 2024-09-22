"""Common zone-related types."""
import hashlib
import dns.enum


class DigestScheme(dns.enum.IntEnum):
    """ZONEMD Scheme"""
    SIMPLE = 1


class DigestHashAlgorithm(dns.enum.IntEnum):
    """ZONEMD Hash Algorithm"""
    SHA384 = 1
    SHA512 = 2


_digest_hashers = {DigestHashAlgorithm.SHA384: hashlib.sha384,
    DigestHashAlgorithm.SHA512: hashlib.sha512}
