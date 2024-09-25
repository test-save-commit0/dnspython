class NullContext:

    def __init__(self, enter_result=None):
        self.enter_result = enter_result

    def __enter__(self):
        return self.enter_result

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    async def __aenter__(self):
        return self.enter_result

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass


class Socket:

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()


class DatagramSocket(Socket):

    def __init__(self, family: int):
        self.family = family

    async def sendto(self, data: bytes, address: tuple) -> int:
        raise NotImplementedError

    async def recvfrom(self, size: int) -> tuple:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError


class StreamSocket(Socket):
    async def connect(self, address: tuple) -> None:
        raise NotImplementedError

    async def sendall(self, data: bytes) -> None:
        raise NotImplementedError

    async def recv(self, size: int) -> bytes:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError


class NullTransport:
    def close(self) -> None:
        pass


class Backend:
    async def make_socket(self, af: int, socktype: int, proto: int = 0, source: tuple = None) -> Socket:
        raise NotImplementedError

    def datagram_connection_required(self) -> bool:
        return False

    async def sleep(self, interval: float) -> None:
        raise NotImplementedError
