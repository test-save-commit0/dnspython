"""Common DNSSEC-related types."""
import dns.enum


class Algorithm(dns.enum.IntEnum):
    RSAMD5 = 1
    DH = 2
    DSA = 3
    ECC = 4
    RSASHA1 = 5
    DSANSEC3SHA1 = 6
    RSASHA1NSEC3SHA1 = 7
    RSASHA256 = 8
    RSASHA512 = 10
    ECCGOST = 12
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    ED25519 = 15
    ED448 = 16
    INDIRECT = 252
    PRIVATEDNS = 253
    PRIVATEOID = 254


class DSDigest(dns.enum.IntEnum):
    """DNSSEC Delegation Signer Digest Algorithm"""
    NULL = 0
    SHA1 = 1
    SHA256 = 2
    GOST = 3
    SHA384 = 4


class NSEC3Hash(dns.enum.IntEnum):
    """NSEC3 hash algorithm"""
    SHA1 = 1
