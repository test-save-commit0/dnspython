import contextvars
import inspect
_in__init__ = contextvars.ContextVar('_immutable_in__init__', default=False)


class _Immutable:
    """Immutable mixin class"""
    __slots__ = ()

    def __setattr__(self, name, value):
        if _in__init__.get() is not self:
            raise TypeError("object doesn't support attribute assignment")
        else:
            super().__setattr__(name, value)

    def __delattr__(self, name):
        if _in__init__.get() is not self:
            raise TypeError("object doesn't support attribute assignment")
        else:
            super().__delattr__(name)
