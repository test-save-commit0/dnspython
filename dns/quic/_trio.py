import socket
import ssl
import struct
import time
import aioquic.quic.configuration
import aioquic.quic.connection
import aioquic.quic.events
import trio
import dns.exception
import dns.inet
from dns._asyncbackend import NullContext
from dns.quic._common import QUIC_MAX_DATAGRAM, AsyncQuicConnection, AsyncQuicManager, BaseQuicStream, UnexpectedEOF


class TrioQuicStream(BaseQuicStream):

    def __init__(self, connection, stream_id):
        super().__init__(connection, stream_id)
        self._wake_up = trio.Condition()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        async with self._wake_up:
            self._wake_up.notify()
        return False


class TrioQuicConnection(AsyncQuicConnection):

    def __init__(self, connection, address, port, source, source_port,
        manager=None):
        super().__init__(connection, address, port, source, source_port,
            manager)
        self._socket = trio.socket.socket(self._af, socket.SOCK_DGRAM, 0)
        self._handshake_complete = trio.Event()
        self._run_done = trio.Event()
        self._worker_scope = None
        self._send_pending = False


class TrioQuicManager(AsyncQuicManager):

    def __init__(self, nursery, conf=None, verify_mode=ssl.CERT_REQUIRED,
        server_name=None):
        super().__init__(conf, verify_mode, TrioQuicConnection, server_name)
        self._nursery = nursery

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        connections = list(self._connections.values())
        for connection in connections:
            await connection.close()
        return False
