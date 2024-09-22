import hashlib
import os
import random
import threading
import time
from typing import Any, Optional


class EntropyPool:

    def __init__(self, seed: Optional[bytes]=None):
        self.pool_index = 0
        self.digest: Optional[bytearray] = None
        self.next_byte = 0
        self.lock = threading.Lock()
        self.hash = hashlib.sha1()
        self.hash_len = 20
        self.pool = bytearray(b'\x00' * self.hash_len)
        if seed is not None:
            self._stir(seed)
            self.seeded = True
            self.seed_pid = os.getpid()
        else:
            self.seeded = False
            self.seed_pid = 0


pool = EntropyPool()
system_random: Optional[Any]
try:
    system_random = random.SystemRandom()
except Exception:
    system_random = None
