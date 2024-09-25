"""trio async I/O library query support"""
import socket
import trio
import trio.socket
import dns._asyncbackend
import dns._features
import dns.exception
import dns.inet
if not dns._features.have('trio'):
    raise ImportError('trio not found or too old')
_lltuple = dns.inet.low_level_address_tuple


class DatagramSocket(dns._asyncbackend.DatagramSocket):

    def __init__(self, socket):
        super().__init__(socket.family)
        self.socket = socket

    async def sendto(self, what, destination, timeout):
        """Send a datagram to the specified destination."""
        try:
            with trio.move_on_after(timeout):
                return await self.socket.sendto(what, destination)
        except trio.TooSlowError:
            raise dns.exception.Timeout(timeout=timeout)

    async def recvfrom(self, size, timeout):
        """Receive a datagram."""
        try:
            with trio.move_on_after(timeout):
                return await self.socket.recvfrom(size)
        except trio.TooSlowError:
            raise dns.exception.Timeout(timeout=timeout)

    async def close(self):
        """Close the socket."""
        self.socket.close()

    async def getpeername(self):
        """Get the remote address to which the socket is connected."""
        return self.socket.getpeername()

    async def getsockname(self):
        """Get the socket's own address."""
        return self.socket.getsockname()


class StreamSocket(dns._asyncbackend.StreamSocket):

    def __init__(self, family, stream, tls=False):
        self.family = family
        self.stream = stream
        self.tls = tls

    async def sendall(self, what, timeout):
        """Send the entire contents of the datagram."""
        try:
            with trio.move_on_after(timeout):
                return await self.stream.send_all(what)
        except trio.TooSlowError:
            raise dns.exception.Timeout(timeout=timeout)

    async def recv(self, size, timeout):
        """Receive data from the stream."""
        try:
            with trio.move_on_after(timeout):
                return await self.stream.receive_some(size)
        except trio.TooSlowError:
            raise dns.exception.Timeout(timeout=timeout)

    async def close(self):
        """Close the stream."""
        await self.stream.aclose()

    async def getpeername(self):
        """Get the remote address to which the socket is connected."""
        return self.stream.socket.getpeername()

    async def getsockname(self):
        """Get the socket's own address."""
        return self.stream.socket.getsockname()


if dns._features.have('doh'):
    import httpcore
    import httpcore._backends.trio
    import httpx
    _CoreAsyncNetworkBackend = httpcore.AsyncNetworkBackend
    _CoreTrioStream = httpcore._backends.trio.TrioStream
    from dns.query import _compute_times, _expiration_for_this_attempt, _remaining


    class _NetworkBackend(_CoreAsyncNetworkBackend):

        def __init__(self, resolver, local_port, bootstrap_address, family):
            super().__init__()
            self._local_port = local_port
            self._resolver = resolver
            self._bootstrap_address = bootstrap_address
            self._family = family


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
    def name(self):
        return 'trio'

    async def make_socket(self, af, socktype, proto=0,
                          source=None, destination=None, timeout=None,
                          ssl_context=None, server_hostname=None):
        """Make a socket based on the parameters."""
        if socktype == socket.SOCK_DGRAM:
            s = trio.socket.socket(af, socktype, proto)
            if source:
                await s.bind(_lltuple(source, af))
            return DatagramSocket(s)
        elif socktype == socket.SOCK_STREAM:
            if destination is None:
                raise ValueError('destination required for stream sockets')
            if timeout is None:
                timeout = 5
            try:
                with trio.move_on_after(timeout):
                    s = await trio.open_tcp_stream(*_lltuple(destination, af))
                    if ssl_context:
                        s = trio.SSLStream(s, ssl_context,
                                           server_hostname=server_hostname)
                        await s.do_handshake()
                    return StreamSocket(af, s, ssl_context is not None)
            except trio.TooSlowError:
                raise dns.exception.Timeout(timeout=timeout)
        raise NotImplementedError('unsupported socket type')

    async def sleep(self, interval):
        """Sleep for the specified interval."""
        await trio.sleep(interval)

    def datagram_connection_required(self):
        """Return True if a connection is required, False otherwise."""
        return False

    def set_socket_options(self, socket, options):
        """Set socket options."""
        for option in options:
            socket.setsockopt(*option)

    def get_socket_family(self, socket):
        """Get the socket family."""
        return socket.family
