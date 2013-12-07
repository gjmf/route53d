"""route53d: DNS transaction signatures."""

import ConfigParser
import logging
from types import StringType

import dns.tsigkeyring

__author__ = 'James Raftery (james@now.ie)'
__vcs_id__ = '$'


class TSIGKeyRing(object):

    def __init__(self, ip, config):
        assert type(ip) is StringType, 'ip is not String obj'
        self.keyring = None
        self.keyname = None

        try:
            self.keyname, self.secret = config.get('tsig', ip).split()
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            logging.debug('no tsig config for %s' % ip)
            return
        except ValueError, e:
            logging.error('invalid tsig config for %s: %s' % (ip, e))
            return
        else:
            logging.debug(self)

        # XXX catch exceptions
        self.keyring = dns.tsigkeyring.from_text({self.keyname: self.secret})
        logging.debug('tsig keyring %s' % self.keyring)


    def __str__(self):
        return 'TSIGKeyRing %s %s' % (self.keyname, self.secret)

