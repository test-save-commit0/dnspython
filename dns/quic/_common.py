import copy
import functools
import socket
import struct
import time
from typing import Any, Optional
import aioquic.quic.configuration
import aioquic.quic.connection
import dns.inet
QUIC_MAX_DATAGRAM = 2048
MAX_SESSION_TICKETS = 8
SESSIONS_TO_DELETE = MAX_SESSION_TICKETS // 4


class UnexpectedEOF(Exception):
    pass


class Buffer:

    def __init__(self):
        self._buffer = b''
        self._seen_end = False

    def add(self, data):
        self._buffer += data

    def get(self, size):
        if len(self._buffer) < size:
            raise UnexpectedEOF
        data = self._buffer[:size]
        self._buffer = self._buffer[size:]
        return data

    def remaining(self):
        return len(self._buffer)

    def set_end(self):
        self._seen_end = True

    def at_end(self):
        return self._seen_end and len(self._buffer) == 0


class BaseQuicStream:

    def __init__(self, connection, stream_id):
        self._connection = connection
        self._stream_id = stream_id
        self._buffer = Buffer()
        self._expecting = 0

    def add(self, data, end):
        self._buffer.add(data)
        if end:
            self._buffer.set_end()

    def get(self, size):
        return self._buffer.get(size)

    def remaining(self):
        return self._buffer.remaining()

    def at_end(self):
        return self._buffer.at_end()

    def expect(self, size):
        self._expecting = size

    def expecting(self):
        return self._expecting


class BaseQuicConnection:

    def __init__(self, connection, address, port, source=None, source_port=
        0, manager=None):
        self._done = False
        self._connection = connection
        self._address = address
        self._port = port
        self._closed = False
        self._manager = manager
        self._streams = {}
        self._af = dns.inet.af_for_address(address)
        self._peer = dns.inet.low_level_address_tuple((address, port))
        if source is None and source_port != 0:
            if self._af == socket.AF_INET:
                source = '0.0.0.0'
            elif self._af == socket.AF_INET6:
                source = '::'
            else:
                raise NotImplementedError
        if source:
            self._source = source, source_port
        else:
            self._source = None

    def close(self):
        if not self._closed:
            self._connection.close()
            self._closed = True
            if self._manager:
                self._manager._remove_connection(self)

    def is_closed(self):
        return self._closed

    def get_stream(self, stream_id):
        if stream_id not in self._streams:
            self._streams[stream_id] = self._connection_factory(self, stream_id)
        return self._streams[stream_id]

    def remove_stream(self, stream_id):
        if stream_id in self._streams:
            del self._streams[stream_id]

    def handle_event(self, event):
        if isinstance(event, aioquic.quic.events.StreamDataReceived):
            stream = self.get_stream(event.stream_id)
            stream.add(event.data, event.end_stream)


class AsyncQuicConnection(BaseQuicConnection):
    pass


class BaseQuicManager:

    def __init__(self, conf, verify_mode, connection_factory, server_name=None
        ):
        self._connections = {}
        self._connection_factory = connection_factory
        self._session_tickets = {}
        if conf is None:
            verify_path = None
            if isinstance(verify_mode, str):
                verify_path = verify_mode
                verify_mode = True
            conf = aioquic.quic.configuration.QuicConfiguration(alpn_protocols
                =['doq', 'doq-i03'], verify_mode=verify_mode, server_name=
                server_name)
            if verify_path is not None:
                conf.load_verify_locations(verify_path)
        self._conf = conf

    def _remove_connection(self, connection):
        key = (connection._address, connection._port)
        if key in self._connections:
            del self._connections[key]

    def _add_connection(self, connection):
        key = (connection._address, connection._port)
        self._connections[key] = connection

    def get_connection(self, address, port):
        key = (address, port)
        return self._connections.get(key)

    def close(self):
        for connection in list(self._connections.values()):
            connection.close()
        self._connections.clear()

    def save_session_ticket(self, ticket):
        if len(self._session_tickets) >= MAX_SESSION_TICKETS:
            tickets_to_remove = sorted(self._session_tickets.items(), key=lambda x: x[1][1])[:SESSIONS_TO_DELETE]
            for key, _ in tickets_to_remove:
                del self._session_tickets[key]
        self._session_tickets[ticket.ticket] = (ticket, time.time())

    def get_session_ticket(self, server_name):
        now = time.time()
        valid_tickets = [(t, ts) for t, (ticket, ts) in self._session_tickets.items() if now - ts < ticket.max_age]
        if valid_tickets:
            return max(valid_tickets, key=lambda x: x[1])[0]
        return None


class AsyncQuicManager(BaseQuicManager):
    pass
