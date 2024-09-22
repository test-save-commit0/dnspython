import importlib.metadata
import itertools
import string
from typing import Dict, List, Tuple


def _version_check(requirement: str) ->bool:
    """Is the requirement fulfilled?

    The requirement must be of the form

        package>=version
    """
    pass


_cache: Dict[str, bool] = {}


def have(feature: str) ->bool:
    """Is *feature* available?

    This tests if all optional packages needed for the
    feature are available and recent enough.

    Returns ``True`` if the feature is available,
    and ``False`` if it is not or if metadata is
    missing.
    """
    pass


def force(feature: str, enabled: bool) ->None:
    """Force the status of *feature* to be *enabled*.

    This method is provided as a workaround for any cases
    where importlib.metadata is ineffective, or for testing.
    """
    pass


_requirements: Dict[str, List[str]] = {'dnssec': ['cryptography>=41'],
    'doh': ['httpcore>=1.0.0', 'httpx>=0.26.0', 'h2>=4.1.0'], 'doq': [
    'aioquic>=0.9.25'], 'idna': ['idna>=3.6'], 'trio': ['trio>=0.23'],
    'wmi': ['wmi>=1.5.1']}
