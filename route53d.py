#!/usr/bin/env python

"""route53d: A DNS interface to the Amazon Route 53 API."""

import sys
import signal
import logging
import os
import pwd
import ConfigParser
from optparse import OptionParser
from multiprocessing import Process, Queue
from types import *

from libroute53d.dnsserver import worker, bind_socket
import libroute53d.monkey
from libroute53d.route53 import status_poller


__author__ = 'James Raftery (james@now.ie)'
__vcs_id__ = '$Id$'



def sighup_handler(signum, frame):
    """SIGHUP handler. Catch and ignore."""
    logging.info('Caught SIGHUP. Ignoring.')


def sigterm_handler(signum, frame):
    """SIGTERM handler. Catch and exit."""
    logging.info('Caught SIGTERM. Exiting.')
    logging.shutdown()
    sys.exit(1)


def sig_handlers():
    """Install signal handlers."""
    signal.signal(signal.SIGHUP,  sighup_handler)
    signal.signal(signal.SIGTERM, sigterm_handler)


def parse_args():
    """Parse command line arguments."""

    parser = OptionParser(usage='usage: %prog [options]')

    parser.add_option('--config', type='string', dest='config',
                      help='Path to configuration file. default: route53d.ini')
    parser.add_option('--debug', action='store_true', dest='debug',
                      help='Print debugging output.')

    parser.set_defaults(debug=False, config='route53d.ini')

    (opt, args) = parser.parse_args()

    return opt


def drop_privs(config):
    """Switch to a non-root user."""

    if os.getuid() != 0:
        logging.debug('nothing to do')
        return

    try:
        username = config.get('server', 'username')
    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError), e:
        logging.error('Cannot run as root, no username in config: %s' % e)
        logging.shutdown()
        sys.exit(1)
    else:
        logging.debug('dropping privs to user %s' % username)

    try:
        user = pwd.getpwnam(username)
    except KeyError, e:
        logging.error('Username not found: %s %s' % (username, e))
        logging.shutdown()
        sys.exit(1)
    else:
        logging.debug('user: %s uid: %d gid: %d' % (username, user.pw_uid,
                                                    user.pw_gid))

    if user.pw_uid == 0:
        logging.error('cannot drop privs to UID 0')
        logging.shutdown()
        sys.exit(1)

    try:
        os.setgid(user.pw_gid)
        os.setgroups([user.pw_gid])
        os.setuid(user.pw_uid)
    except OSError, e:
        logging.error('Could not drop privs: %s %s' % (username, e))
        logging.shutdown()
        sys.exit(1)


def parse_config(filename):
    """Parse the config file and return an instance of a ConfigParser."""

    config = ConfigParser.SafeConfigParser()

    try:
        config.readfp(open(filename))
    except Exception, e:
        print('error parsing %s config file: %s' % (filename, e))
        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit(1)

    return config


def setup_logging(debug):
    """Configure logging module parameters."""

    datefmt='%Y-%m-%d %H:%M.%S %Z'
    if debug:
        logging.basicConfig(level=logging.DEBUG, datefmt=datefmt,
            format='%(asctime)s - %(process)d - %(levelname)s - ' \
                   '%(filename)s:%(lineno)d %(funcName)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, datefmt=datefmt,
            format='%(asctime)s - %(process)d - %(levelname)s - %(message)s')


def main():
    """Run the show."""

    opt = parse_args()
    cfg = parse_config(opt.config)
    setup_logging(opt.debug)
    libroute53d.monkey.monkey_patch_all()
    logging.info('Starting')
    sig_handlers()
    server = bind_socket(cfg)
    drop_privs(cfg)

    pending_change_q = Queue()
    server.pending_change_q = pending_change_q
    server.config = cfg

    # Fire up worker processes
    try:
        for i in range(cfg.getint('server','processes')):
            Process(target=worker, args=(server,)).start()
    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError), e:
        logging.error('config error: %s' % e)
        return 1

    # Parent polls for pending changes
    try:
        status_poller(pending_change_q)
    except AssertionError:
        raise
    except Exception, e:
        logging.error('Exiting. Caught exception %s' % e)
        return 1


    #####   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #####


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.info('caught Ctrl-C, stopping')
    finally:
        logging.shutdown()


#
# EOF
#
