import collections
import random
import struct
from typing import Any, List
import dns.exception
import dns.ipv4
import dns.ipv6
import dns.name
import dns.rdata


class Gateway:
    """A helper class for the IPSECKEY gateway and AMTRELAY relay fields"""
    name = ''

    def __init__(self, type, gateway=None):
        self.type = dns.rdata.Rdata._as_uint8(type)
        self.gateway = gateway
        self._check()


class Bitmap:
    """A helper class for the NSEC/NSEC3/CSYNC type bitmaps"""
    type_name = ''

    def __init__(self, windows=None):
        last_window = -1
        self.windows = windows
        for window, bitmap in self.windows:
            if not isinstance(window, int):
                raise ValueError(f'bad {self.type_name} window type')
            if window <= last_window:
                raise ValueError(f'bad {self.type_name} window order')
            if window > 256:
                raise ValueError(f'bad {self.type_name} window number')
            last_window = window
            if not isinstance(bitmap, bytes):
                raise ValueError(f'bad {self.type_name} octets type')
            if len(bitmap) == 0 or len(bitmap) > 32:
                raise ValueError(f'bad {self.type_name} octets')


_no_weight = 0.1
