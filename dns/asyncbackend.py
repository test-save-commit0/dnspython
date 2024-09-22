from typing import Dict
import dns.exception
from dns._asyncbackend import Backend, DatagramSocket, Socket, StreamSocket
_default_backend = None
_backends: Dict[str, Backend] = {}
_no_sniffio = False


class AsyncLibraryNotFoundError(dns.exception.DNSException):
    pass


def get_backend(name: str) ->Backend:
    """Get the specified asynchronous backend.

    *name*, a ``str``, the name of the backend.  Currently the "trio"
    and "asyncio" backends are available.

    Raises NotImplementedError if an unknown backend name is specified.
    """
    pass


def sniff() ->str:
    """Attempt to determine the in-use asynchronous I/O library by using
    the ``sniffio`` module if it is available.

    Returns the name of the library, or raises AsyncLibraryNotFoundError
    if the library cannot be determined.
    """
    pass


def get_default_backend() ->Backend:
    """Get the default backend, initializing it if necessary."""
    pass


def set_default_backend(name: str) ->Backend:
    """Set the default backend.

    It's not normally necessary to call this method, as
    ``get_default_backend()`` will initialize the backend
    appropriately in many cases.  If ``sniffio`` is not installed, or
    in testing situations, this function allows the backend to be set
    explicitly.
    """
    pass
