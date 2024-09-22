import base64
import dns.exception
import dns.immutable
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class OPENPGPKEY(dns.rdata.Rdata):
    """OPENPGPKEY record"""

    def __init__(self, rdclass, rdtype, key):
        super().__init__(rdclass, rdtype)
        self.key = self._as_bytes(key)
