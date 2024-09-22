import selectors
import socket
import ssl
import struct
import threading
import time
import aioquic.quic.configuration
import aioquic.quic.connection
import aioquic.quic.events
import dns.exception
import dns.inet
from dns.quic._common import QUIC_MAX_DATAGRAM, BaseQuicConnection, BaseQuicManager, BaseQuicStream, UnexpectedEOF
if hasattr(selectors, 'PollSelector'):
    _selector_class = selectors.PollSelector
else:
    _selector_class = selectors.SelectSelector


class SyncQuicStream(BaseQuicStream):

    def __init__(self, connection, stream_id):
        super().__init__(connection, stream_id)
        self._wake_up = threading.Condition()
        self._lock = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        with self._wake_up:
            self._wake_up.notify()
        return False


class SyncQuicConnection(BaseQuicConnection):

    def __init__(self, connection, address, port, source, source_port, manager
        ):
        super().__init__(connection, address, port, source, source_port,
            manager)
        self._socket = socket.socket(self._af, socket.SOCK_DGRAM, 0)
        if self._source is not None:
            try:
                self._socket.bind(dns.inet.low_level_address_tuple(self.
                    _source, self._af))
            except Exception:
                self._socket.close()
                raise
        self._socket.connect(self._peer)
        self._send_wakeup, self._receive_wakeup = socket.socketpair()
        self._receive_wakeup.setblocking(False)
        self._socket.setblocking(False)
        self._handshake_complete = threading.Event()
        self._worker_thread = None
        self._lock = threading.Lock()


class SyncQuicManager(BaseQuicManager):

    def __init__(self, conf=None, verify_mode=ssl.CERT_REQUIRED,
        server_name=None):
        super().__init__(conf, verify_mode, SyncQuicConnection, server_name)
        self._lock = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        connections = list(self._connections.values())
        for connection in connections:
            connection.close()
        return False
