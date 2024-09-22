import asyncio
import socket
import ssl
import struct
import time
import aioquic.quic.configuration
import aioquic.quic.connection
import aioquic.quic.events
import dns.asyncbackend
import dns.exception
import dns.inet
from dns.quic._common import QUIC_MAX_DATAGRAM, AsyncQuicConnection, AsyncQuicManager, BaseQuicStream, UnexpectedEOF


class AsyncioQuicStream(BaseQuicStream):

    def __init__(self, connection, stream_id):
        super().__init__(connection, stream_id)
        self._wake_up = asyncio.Condition()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        async with self._wake_up:
            self._wake_up.notify()
        return False


class AsyncioQuicConnection(AsyncQuicConnection):

    def __init__(self, connection, address, port, source, source_port,
        manager=None):
        super().__init__(connection, address, port, source, source_port,
            manager)
        self._socket = None
        self._handshake_complete = asyncio.Event()
        self._socket_created = asyncio.Event()
        self._wake_timer = asyncio.Condition()
        self._receiver_task = None
        self._sender_task = None


class AsyncioQuicManager(AsyncQuicManager):

    def __init__(self, conf=None, verify_mode=ssl.CERT_REQUIRED,
        server_name=None):
        super().__init__(conf, verify_mode, AsyncioQuicConnection, server_name)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        connections = list(self._connections.values())
        for connection in connections:
            await connection.close()
        return False
