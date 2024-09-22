"""DNS GENERATE range conversion."""
from typing import Tuple
import dns


def from_text(text: str) ->Tuple[int, int, int]:
    """Convert the text form of a range in a ``$GENERATE`` statement to an
    integer.

    *text*, a ``str``, the textual range in ``$GENERATE`` form.

    Returns a tuple of three ``int`` values ``(start, stop, step)``.
    """
    pass
