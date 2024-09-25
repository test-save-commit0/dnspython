"""asyncio library query support"""
import asyncio
import socket
import sys
import dns._asyncbackend
import dns._features
import dns.exception
import dns.inet
_is_win32 = sys.platform == 'win32'


class _DatagramProtocol:

    def __init__(self):
        self.transport = None
        self.recvfrom = None


class DatagramSocket(dns._asyncbackend.DatagramSocket):

    def __init__(self, family, transport, protocol):
        super().__init__(family)
        self.transport = transport
        self.protocol = protocol

    async def sendto(self, what, destination, timeout):
        self.transport.sendto(what, destination)

    async def recvfrom(self, size, timeout):
        self.protocol.recvfrom = asyncio.Future()
        try:
            return await asyncio.wait_for(self.protocol.recvfrom, timeout)
        except asyncio.TimeoutError:
            raise dns.exception.Timeout

    async def close(self):
        self.transport.close()


class StreamSocket(dns._asyncbackend.StreamSocket):

    def __init__(self, af, reader, writer):
        self.family = af
        self.reader = reader
        self.writer = writer

    async def sendall(self, what, timeout):
        self.writer.write(what)
        await asyncio.wait_for(self.writer.drain(), timeout)

    async def recv(self, size, timeout):
        try:
            return await asyncio.wait_for(self.reader.read(size), timeout)
        except asyncio.TimeoutError:
            raise dns.exception.Timeout

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()


if dns._features.have('doh'):
    import anyio
    import httpcore
    import httpcore._backends.anyio
    import httpx
    _CoreAsyncNetworkBackend = httpcore.AsyncNetworkBackend
    _CoreAnyIOStream = httpcore._backends.anyio.AnyIOStream
    from dns.query import _compute_times, _expiration_for_this_attempt, _remaining


    class _NetworkBackend(_CoreAsyncNetworkBackend):

        def __init__(self, resolver, local_port, bootstrap_address, family):
            super().__init__()
            self._local_port = local_port
            self._resolver = resolver
            self._bootstrap_address = bootstrap_address
            self._family = family
            if local_port != 0:
                raise NotImplementedError(
                    'the asyncio transport for HTTPX cannot set the local port'
                    )


    class _HTTPTransport(httpx.AsyncHTTPTransport):

        def __init__(self, *args, local_port=0, bootstrap_address=None,
            resolver=None, family=socket.AF_UNSPEC, **kwargs):
            if resolver is None:
                import dns.asyncresolver
                resolver = dns.asyncresolver.Resolver()
            super().__init__(*args, **kwargs)
            self._pool._network_backend = _NetworkBackend(resolver,
                local_port, bootstrap_address, family)
else:
    _HTTPTransport = dns._asyncbackend.NullTransport


class Backend(dns._asyncbackend.Backend):
    async def make_socket(self, af, socktype, proto=0, source=None, destination=None,
                          timeout=None, ssl_context=None, server_hostname=None):
        if socktype == socket.SOCK_DGRAM:
            transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
                lambda: _DatagramProtocol(),
                local_addr=source,
                remote_addr=destination,
                family=af,
                proto=proto
            )
            return DatagramSocket(af, transport, protocol)
        elif socktype == socket.SOCK_STREAM:
            if destination is None:
                raise ValueError("destination required for stream sockets")
            host, port = destination
            if timeout is not None:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_context, 
                                            server_hostname=server_hostname),
                    timeout
                )
            else:
                reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context, 
                                                               server_hostname=server_hostname)
            return StreamSocket(af, reader, writer)
        else:
            raise NotImplementedError(f"unsupported socket type {socktype}")

    async def sleep(self, interval):
        await asyncio.sleep(interval)

    def datagram_connection_required(self):
        return not _is_win32

    def get_transport_class(self):
        return _HTTPTransport
