import struct
import dns.exception
import dns.immutable
import dns.rdata
_pows = tuple(10 ** i for i in range(0, 11))
_default_size = 100.0
_default_hprec = 1000000.0
_default_vprec = 1000.0
_MAX_LATITUDE = 2147483648 + 90 * 3600000
_MIN_LATITUDE = 2147483648 - 90 * 3600000
_MAX_LONGITUDE = 2147483648 + 180 * 3600000
_MIN_LONGITUDE = 2147483648 - 180 * 3600000


@dns.immutable.immutable
class LOC(dns.rdata.Rdata):
    """LOC record"""
    __slots__ = ['latitude', 'longitude', 'altitude', 'size',
        'horizontal_precision', 'vertical_precision']

    def __init__(self, rdclass, rdtype, latitude, longitude, altitude, size
        =_default_size, hprec=_default_hprec, vprec=_default_vprec):
        """Initialize a LOC record instance.

        The parameters I{latitude} and I{longitude} may be either a 4-tuple
        of integers specifying (degrees, minutes, seconds, milliseconds),
        or they may be floating point values specifying the number of
        degrees. The other parameters are floats. Size, horizontal precision,
        and vertical precision are specified in centimeters."""
        super().__init__(rdclass, rdtype)
        if isinstance(latitude, int):
            latitude = float(latitude)
        if isinstance(latitude, float):
            latitude = _float_to_tuple(latitude)
        _check_coordinate_list(latitude, -90, 90)
        self.latitude = tuple(latitude)
        if isinstance(longitude, int):
            longitude = float(longitude)
        if isinstance(longitude, float):
            longitude = _float_to_tuple(longitude)
        _check_coordinate_list(longitude, -180, 180)
        self.longitude = tuple(longitude)
        self.altitude = float(altitude)
        self.size = float(size)
        self.horizontal_precision = float(hprec)
        self.vertical_precision = float(vprec)

    @property
    def float_latitude(self):
        """latitude as a floating point value"""
        return _tuple_to_float(self.latitude)

    @property
    def float_longitude(self):
        """longitude as a floating point value"""
        return _tuple_to_float(self.longitude)

def _tuple_to_float(tuple_coord):
    """Convert a coordinate tuple to a float value."""
    degrees, minutes, seconds, milliseconds = tuple_coord
    return degrees + (minutes / 60.0) + (seconds / 3600.0) + (milliseconds / 3600000.0)

def _float_to_tuple(float_coord):
    """Convert a float coordinate to a tuple."""
    degrees = int(float_coord)
    minutes = int((float_coord - degrees) * 60)
    seconds = int(((float_coord - degrees) * 60 - minutes) * 60)
    milliseconds = int((((float_coord - degrees) * 60 - minutes) * 60 - seconds) * 1000)
    return (degrees, minutes, seconds, milliseconds)

def _check_coordinate_list(coordinate, low, high):
    """Check if the coordinate is within the specified range."""
    if len(coordinate) != 4:
        raise dns.exception.SyntaxError('LOC coordinate must be a 4-tuple')
    for i in range(4):
        if not isinstance(coordinate[i], int):
            raise dns.exception.SyntaxError('LOC coordinate must be integers')
    degrees, minutes, seconds, milliseconds = coordinate
    if degrees < low or degrees > high:
        raise dns.exception.SyntaxError(f'LOC degrees must be between {low} and {high}')
    if minutes < 0 or minutes > 59:
        raise dns.exception.SyntaxError('LOC minutes must be between 0 and 59')
    if seconds < 0 or seconds > 59:
        raise dns.exception.SyntaxError('LOC seconds must be between 0 and 59')
    if milliseconds < 0 or milliseconds > 999:
        raise dns.exception.SyntaxError('LOC milliseconds must be between 0 and 999')
