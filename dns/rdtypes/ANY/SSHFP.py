import binascii
import struct
import dns.immutable
import dns.rdata
import dns.rdatatype


@dns.immutable.immutable
class SSHFP(dns.rdata.Rdata):
    """SSHFP record"""
    __slots__ = ['algorithm', 'fp_type', 'fingerprint']

    def __init__(self, rdclass, rdtype, algorithm, fp_type, fingerprint):
        super().__init__(rdclass, rdtype)
        self.algorithm = self._as_uint8(algorithm)
        self.fp_type = self._as_uint8(fp_type)
        self.fingerprint = self._as_bytes(fingerprint, True)
