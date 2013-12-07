"""Custom exceptions for route53d."""

__author__ = 'James Raftery (james@now.ie)'
__vcs_id__ = '$Id$'


class Route53Exception(Exception):
    """Base class for custom exceptions raised by route53d."""
    pass


class EndOfDataException(Route53Exception):
    """No more zone data is available."""
    pass

