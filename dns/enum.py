import enum
from typing import Type, TypeVar, Union
TIntEnum = TypeVar('TIntEnum', bound='IntEnum')


class IntEnum(enum.IntEnum):

    @classmethod
    def make(cls: Type[TIntEnum], value: Union[int, str]) ->TIntEnum:
        """Convert text or a value into an enumerated type, if possible.

        *value*, the ``int`` or ``str`` to convert.

        Raises a class-specific exception if a ``str`` is provided that
        cannot be converted.

        Raises ``ValueError`` if the value is out of range.

        Returns an enumeration from the calling class corresponding to the
        value, if one is defined, or an ``int`` otherwise.
        """
        pass
