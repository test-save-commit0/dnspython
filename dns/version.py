"""dnspython release version information."""
MAJOR = 2
MINOR = 6
MICRO = 1
RELEASELEVEL = 15
SERIAL = 0
if RELEASELEVEL == 15:
    version = '%d.%d.%d' % (MAJOR, MINOR, MICRO)
elif RELEASELEVEL == 0:
    version = '%d.%d.%ddev%d' % (MAJOR, MINOR, MICRO, SERIAL)
elif RELEASELEVEL == 12:
    version = '%d.%d.%drc%d' % (MAJOR, MINOR, MICRO, SERIAL)
else:
    version = '%d.%d.%d%x%d' % (MAJOR, MINOR, MICRO, RELEASELEVEL, SERIAL)
hexversion = (MAJOR << 24 | MINOR << 16 | MICRO << 8 | RELEASELEVEL << 4 |
    SERIAL)
