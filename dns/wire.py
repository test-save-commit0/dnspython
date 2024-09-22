import contextlib
import struct
from typing import Iterator, Optional, Tuple
import dns.exception
import dns.name


class Parser:

    def __init__(self, wire: bytes, current: int=0):
        self.wire = wire
        self.current = 0
        self.end = len(self.wire)
        if current:
            self.seek(current)
        self.furthest = current
