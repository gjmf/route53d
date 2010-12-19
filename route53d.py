#!/usr/bin/env python

#
# Copyright (c) 2010 James Raftery <james@now.ie>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the author nor the names of contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import signal
import logging
import select
import sys
import os
import pwd
import SocketServer
import ConfigParser
import binascii
import struct
from optparse import OptionParser
from multiprocessing import Process, current_process
from types import *
import dns.message
import dns.query
import dns.zone
import dns.rdatatype
import boto.route53

#############################################################################

class Route53HostedZoneRequest:

    Route53APIXMLRRSetChangeHeader = """
      <ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2010-10-01/">
       <ChangeBatch>
    """

    Route53APIXMLRRSetChangeFooter = """
       </ChangeBatch>
      </ChangeResourceRecordSetsRequest>
    """

    def __init__(self, zonename):
        assert type(zonename) is dns.name.Name, 'zonename is not Name obj'
        self.additions = []
        self.deletions = []
        try:
            self.zoneid = config.get('hostedzone', zonename.to_text(omit_final_dot=True))
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            logging.error('no zoneid for %s' % zonename)
            raise
        else:
            logging.debug('found %s zoneid: %s' % (zonename, self.zoneid))

        assert type(self.zoneid) is StringType, 'zoneid is not String obj'


    def add(self, rrset):
        assert type(rrset) is dns.rrset.RRset, 'rrset is not RRset obj'
        self.additions.append(rrset)


    def delete(self, rrset):
        assert type(rrset) is dns.rrset.RRset, 'rrset is not RRset obj'
        self.deletions.append(rrset)


    def to_xml(self, comment=None):
        # TODO
        #  Max of 1000 ResourceRecord elements
        #  Max of 32000 characters in record data
        xml  = """<?xml version="1.0" encoding="UTF-8"?>"""
        xml += self.Route53APIXMLRRSetChangeHeader
        xml += '    <Comment>%s</Comment>\n' % comment
        xml += '        <Changes>'
        xml += self.rrset_xml('DELETE', self.deletions)
        xml += self.rrset_xml('CREATE', self.additions)
        xml += '</Changes>'
        xml += self.Route53APIXMLRRSetChangeFooter
        return xml


    def rrset_xml(self, action, rrsetlist):
        assert type(action)    is StringType, 'action is not String obj'
        assert type(rrsetlist) is ListType, 'rrsetlist is not List obj'

        return ''.join(["""
         <Change>
          <Action>%s</Action>
          <ResourceRecordSet>
           <Name>%s</Name>
           <Type>%s</Type>
           <TTL>%d</TTL>
           <ResourceRecords>
            %s
           </ResourceRecords>
          </ResourceRecordSet>
         </Change>
        """ % (action, r.name, dns.rdatatype.to_text(r.rdtype), r.ttl, \
                self.rr_xml(r)) for r in rrsetlist])


    def rr_xml(self, rrset):
        assert type(rrset) is dns.rrset.RRset, 'rrset is not RRset obj'
        return '\n'.join(['<ResourceRecord><Value>%s</Value></ResourceRecord>' \
                                % r for r in rrset])

    def submit(self, serial=None):

        if not self.additions and not self.deletions:
            logging.debug('nothing to do')
            return

        xml = self.to_xml()
        logging.debug(xml)

        try:
            dryrun = config.getint('server', 'dry-run')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            dryrun = 0

        if dryrun:
            logging.debug('Dry-run. No change submitted')
            return

        cnxn = boto.route53.Route53Connection()
        result = cnxn.change_rrsets(self.zoneid, xml)
        logging.debug(result)

        try:
            info = result.get('ChangeResourceRecordSetsResponse').get('ChangeInfo')
        except KeyError:
            # XXX need to parse error response
            logging.error('invalid response: %s' % result)
            raise
        else:
            logging.info('ChangeID: %s Status: %s' % \
                            (info.get('Id'), info.get('Status')))

#############################################################################

class UDPDNSHandler(SocketServer.BaseRequestHandler):
    """Process UDP DNS messages."""

    def handle(self):
        """Basic sanity check then handover to the opcode-specific function."""

        remote_ip = self.client_address[0]

        try:
            msg = dns.message.from_wire(self.request[0])
        except Exception, e:
            logging.error('malformed message from %s: %s' % (remote_ip, e))
            logging.debug('packet: %s' % binascii.hexlify(self.request[0]))
            return

        # XXX
        #  Check for QR?
        if msg.rcode() != dns.rcode.NOERROR:
            logging.error('RCODE not NOERROR from %s' % remote_ip)
            response = self.formerr(msg)
        elif msg.opcode() == dns.opcode.QUERY:
            response = self.handle_query(msg)
        elif msg.opcode() == dns.opcode.NOTIFY:
            response = self.handle_notify(msg)
        elif msg.opcode() == dns.opcode.UPDATE:
            response = self.handle_update(msg)
        else:
            logging.warn('unsupported opcode from %s: %d' % \
                            (remote_ip, msg.opcode()))
            response = self.notimp(msg)

        assert type(response) is dns.message.Message, 'response is not Message obj'
        self.request[1].sendto(response.to_wire(), self.client_address)


    def handle_update(self, msg):
        """Process an update message."""

        remote_ip = self.client_address[0]

        assert type(msg) is dns.message.Message, 'msg is not Message obj'

        try:
            qname, qclass, qtype = self.parse_question(msg)
        except AssertionError:
            raise
        except Exception, e:
            logging.warn('UPDATE parse error from %s: %s' % (remote_ip, e))
            return(self.servfail(msg))
        else:
            logging.info('UPDATE from %s: %s %s %s' % (remote_ip, qname, \
                                    dns.rdataclass.to_text(qclass), \
                                    dns.rdatatype.to_text(qtype)))

        assert type(qname)  is dns.name.Name, 'qname is not Name obj'
        assert type(qclass) is IntType, 'qclass is not Int obj'
        assert type(qtype)  is IntType, 'qtype is not Int obj'

        if qtype != dns.rdatatype.SOA or qclass != dns.rdataclass.IN:
            logging.warn('UPDATE invalid question %s' % remote_ip)
            return self.formerr(msg)

        if len(msg.answer):
            # no support for prereq's
            logging.warn('UPDATE unsupported prereqs from %s' % remote_ip)
            return self.servfail(msg)

        response = dns.message.make_response(msg)
        assert type(response) is dns.message.Message, 'response is not Message obj'

        if len(msg.authority) == 0:
            logging.debug('nothing to do')
            return response

        Route53Request = Route53HostedZoneRequest(qname)

        for rrset in msg.authority:

            if not rrset.name.is_subdomain(qname):
                logging.warn('UPDATE NOTZONE from %s: %s' % (remote_ip, e))
                response.set_rcode(dns.rcode.NOTZONE)
                return response

            if rrset.rdclass == dns.rdataclass.IN:

                # addition
                logging.debug('UPDATE add rrset: %s' % rrset)
                if rrset.rdtype in (dns.rdatatype.ANY, dns.rdatatype.AXFR, \
                                    dns.rdatatype.IXFR, dns.rdatatype.MAILA, \
                                    dns.rdatatype.MAILB):
                    logging.error('UPDATE bad rdtype from %s: %s' % \
                                    (remote_ip, rrset))
                    response.set_rcode(dns.rcode.FORMERR)
                    return response

                Route53Request.add(rrset)

            elif rrset.rdclass == dns.rdataclass.ANY:

                # name or rrset deletion
                if rrset.ttl != 0:
                    logging.error('UPDATE bad ttl from %s: %s' % \
                                    (remote_ip, rrset))
                    response.set_rcode(dns.rcode.FORMERR)
                    return response

                if rrset.rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR, \
                                    dns.rdatatype.MAILA, dns.rdatatype.MAILB):
                    logging.error('UPDATE bad rdtype from %s: %s' % \
                                    (remote_ip, rrset))
                    response.set_rcode(dns.rcode.FORMERR)
                    return response

                if rrset.rdtype == dns.rdatatype.ANY:
                    logging.warn('UPDATE unsupported delete name: %s' % rrset)
                else:
                    logging.warn('UPDATE unsupported delete rrset: %s' % rrset)

                response.set_rcode(dns.rcode.SERVFAIL)
                return response

            elif rrset.rdclass == dns.rdataclass.NONE:

                # specific rr deletion
                if rrset.ttl != 0:
                    logging.error('UPDATE bad ttl from %s: %s' % \
                                    (remote_ip, rrset))
                    response.set_rcode(dns.rcode.FORMERR)
                    return response

                if rrset.rdtype in (dns.rdatatype.ANY, dns.rdatatype.AXFR, \
                                    dns.rdatatype.IXFR, dns.rdatatype.MAILA, \
                                    dns.rdatatype.MAILB):
                    logging.error('UPDATE bad rdtype from %s: %s' % \
                                    (remote_ip, rrset))
                    response.set_rcode(dns.rcode.FORMERR)
                    return response

                # XXX TTL! Have to fake it for the moment.
                try:
                    rrset.ttl = config.getint('kludge', 'delete_ttl')
                except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
                    logging.error('no delete ttl for %s' % qname)
                    return self.servfail(msg)
                else:
                    logging.debug('found delete ttl: %d' % rrset.ttl)

                logging.debug('UPDATE delete rr: %s' % rrset)
                Route53Request.delete(rrset)

            else:
                logging.warn('UPDATE unknown rr from %s: %s' % (remote_ip, rrset))
                response.set_rcode(dns.rcode.FORMERR)
                return response

        try:
            Route53Request.submit(qname)
        except AssertionError:
            raise
        except boto.route53.exception.DNSServerError, e:
            logging.error('UPDATE API call failed: %s - %s - %s' % (e.code, e.message, str(e)))
            response.set_rcode(dns.rcode.SERVFAIL)
        except Exception, e:
            logging.error('UPDATE API call failed: %s' % e)
            response.set_rcode(dns.rcode.SERVFAIL)
        else:
            logging.debug('UPDATE successful')

        return(response)


    def handle_notify(self, msg):
        """Process an update message."""

        remote_ip = self.client_address[0]

        assert type(msg) is dns.message.Message, 'msg is not Message obj'

        try:
            qname, qclass, qtype = self.parse_question(msg)
        except AssertionError:
            raise
        except Exception, e:
            logging.warn('NOTIFY parse error from %s: %s' % (remote_ip, e))
            return self.servfail(msg)
        else:
            logging.info('NOTIFY from %s: %s %s %s' % (remote_ip, qname, \
                                    dns.rdataclass.to_text(qclass), \
                                    dns.rdatatype.to_text(qtype)))

        assert type(qname)  is dns.name.Name, 'qname is not Name obj'
        assert type(qclass) is IntType, 'qclass is not Int obj'
        assert type(qtype)  is IntType, 'qtype is not Int obj'

        if qtype != dns.rdatatype.SOA or qclass != dns.rdataclass.IN:
            logging.warn('NOTIFY bad qclass/qtype from %s' % remote_ip)
            return self.servfail(msg)

        if not (msg.flags & dns.flags.AA):
            logging.warn('NOTIFY !AA from %s' % remote_ip)

        #
        # invoke XFRClient()
        #

        # XXX
        # For now, respond in the affirmative to anything
        response = dns.message.make_response(msg)
        response.flags |= dns.flags.AA
        return response


    def handle_query(self, msg):
        """Process a query message."""

        #
        # Not ready for release yet
        #
        remote_ip = self.client_address[0]

        assert type(msg) is dns.message.Message, 'msg is not Message obj'

        try:
            qname, qclass, qtype = self.parse_question(msg)
        except AssertionError:
            raise
        except Exception, e:
            logging.warn('QUERY parse error from %s: %s' % (remote_ip, e))
            return(self.servfail(msg))
        else:
            logging.info('QUERY from %s: %s %s %s' % (remote_ip, qname, \
                                    dns.rdataclass.to_text(qclass), \
                                    dns.rdatatype.to_text(qtype)))

        assert type(qname)  is dns.name.Name, 'qname is not Name obj'
        assert type(qclass) is IntType, 'qclass is not Int obj'
        assert type(qtype)  is IntType, 'qtype is not Int obj'

        response = dns.message.make_response(msg)
        return response


    def parse_question(self, msg):
        """Read the qname, qclass and qtype from the question section."""

        if len(msg.question) != 1:
            logging.warn('Question count != 1 from %s')
            raise Exception('Question count != 1')

        try:
            n, c, t = msg.question[0].name, msg.question[0].rdclass, \
                        msg.question[0].rdtype
        except IndexError:
            remote_ip = self.client_address[0]
            logging.error('missing question from %s: %s' % (remote_ip, e))
            raise
        else:
            return (n, c, t)


    # One-liners for replies with common error rcodes
    def servfail(self, msg):
        return dns.message.make_response(msg).set_rcode(dns.rcode.SERVFAIL)

    def notimp(self, msg):
        return dns.message.make_response(msg).set_rcode(dns.rcode.NOTIMP)

    def formerr(self, msg):
        return dns.message.make_response(msg).set_rcode(dns.rcode.FORMERR)

#############################################################################

#
# __main__
#

# This is a modified version of _WireReader._get_section from dnspython 1.9.2.
# It doesn't munge the RR class in Update section RRs and always decodes the
# RDATA.
def _get_section(self, section, count):
    """Read the next I{count} records from the wire data and add them to
    the specified section.
    @param section: the section of the message to which to add records
    @type section: list of dns.rrset.RRset objects
    @param count: the number of records to read
    @type count: int"""

    if self.updating or self.one_rr_per_rrset:
        force_unique = True
    else:
        force_unique = False
    seen_opt = False
    for i in xrange(0, count):
        rr_start = self.current
        (name, used) = dns.name.from_wire(self.wire, self.current)
        absolute_name = name
        if not self.message.origin is None:
            name = name.relativize(self.message.origin)
        self.current = self.current + used
        (rdtype, rdclass, ttl, rdlen) = \
                 struct.unpack('!HHIH',
                               self.wire[self.current:self.current + 10])
        self.current = self.current + 10
        if rdtype == dns.rdatatype.OPT:
            if not section is self.message.additional or seen_opt:
                raise BadEDNS
            self.message.payload = rdclass
            self.message.ednsflags = ttl
            self.message.edns = (ttl & 0xff0000) >> 16
            self.message.options = []
            current = self.current
            optslen = rdlen
            while optslen > 0:
                (otype, olen) = \
                        struct.unpack('!HH',
                                      self.wire[current:current + 4])
                current = current + 4
                opt = dns.edns.option_from_wire(otype, self.wire, current, olen)
                self.message.options.append(opt)
                current = current + olen
                optslen = optslen - 4 - olen
            seen_opt = True
        elif rdtype == dns.rdatatype.TSIG:
            if not (section is self.message.additional and
                    i == (count - 1)):
                raise BadTSIG
            if self.message.keyring is None:
                raise UnknownTSIGKey('got signed message without keyring')
            secret = self.message.keyring.get(absolute_name)
            if secret is None:
                raise UnknownTSIGKey("key '%s' unknown" % name)
            self.message.tsig_ctx = \
                                  dns.tsig.validate(self.wire,
                                      absolute_name,
                                      secret,
                                      int(time.time()),
                                      self.message.request_mac,
                                      rr_start,
                                      self.current,
                                      rdlen,
                                      self.message.tsig_ctx,
                                      self.message.multi,
                                      self.message.first)
            self.message.had_tsig = True
        else:
            if ttl < 0:
                ttl = 0
            if self.updating and \
               (rdclass == dns.rdataclass.ANY or
                rdclass == dns.rdataclass.NONE):
                deleting = rdclass
                #rdclass = self.zone_rdclass
            else:
                deleting = None

            rd = dns.rdata.from_wire(rdclass, rdtype, self.wire,
                                     self.current, rdlen,
                                     self.message.origin)
            if deleting == dns.rdataclass.ANY or \
               (deleting == dns.rdataclass.NONE and \
                section == self.message.answer):
                covers = dns.rdatatype.NONE
            else:
                covers = rd.covers()

            if self.message.xfr and rdtype == dns.rdatatype.SOA:
                force_unique = True
            rrset = self.message.find_rrset(section, name,
                                            rdclass, rdtype, covers,
                                            deleting, True, force_unique)
            if not rd is None:
                rrset.add(rd, ttl)

        self.current = self.current + rdlen

# Insert our _get_section into dns.message
dns.message._WireReader._get_section = _get_section


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


def drop_privs():
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
        logging.debug('user: %s uid: %d gid: %d' % (username, user.pw_uid, user.pw_gid))

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


def bind_socket():
    """Create a SocketServer.UDPServer instance."""

    try:
        ip   = config.get('server', 'listen_ip')
        port = config.getint('server', 'listen_port')
    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError), e:
        logging.error('no ip or port in config: %s' % e)
        logging.shutdown()
        sys.exit(1)
    else:
        logging.debug('ip: %s port: %d' % (ip, port))

    try:
        server = SocketServer.UDPServer((ip, port), UDPDNSHandler)
    except Exception, e:
        logging.error('Cannot bind socket: %s' % e)
        logging.shutdown()
        sys.exit(1)
    else:
        logging.debug('server: %s' % server)
        return server


def parse_config(file):
    """Parse the config file into the `config' global variable."""

    global config
    config = ConfigParser.SafeConfigParser()

    try:
        config.readfp(open(file))
    except Exception, e:
        print('error parsing %s config file: %s' % (file, e))
        logging.shutdown()
        sys.exit(1)


def setup_logging(debug):

    datefmt='%Y-%m-%d %H:%M.%S %Z'
    if debug:
        logging.basicConfig(level=logging.DEBUG, datefmt=datefmt, \
            format='%(asctime)s - %(process)d - %(levelname)s - %(filename)s:%(lineno)d %(funcName)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, datefmt=datefmt, \
            format='%(asctime)s - %(process)d - %(levelname)s - %(message)s')


def worker(server):
    """Worker loop.

    Jumping to a signal handler can yield harmless select.error exceptions.
    Catch them and reattach to the socket.

    """

    while 1:
        try:
            logging.debug('Starting worker')
            server.serve_forever()
        except select.error:
            # ignore the interrupted syscall spew if we catch a signal
            pass
        except KeyboardInterrupt:
            logging.info('Exiting.')
            break
        except AssertionError:
            raise
        except Exception, e:
            logging.error('Exiting. Caught exception %s' % e)
            return 1

    return 0


def main():
    """Run the show."""

    opt = parse_args()
    parse_config(opt.config)
    setup_logging(opt.debug)
    logging.info('Starting')
    sig_handlers()
    server = bind_socket()
    drop_privs()

    # Fire up worker processes
    try:
        for i in range(config.getint('server','processes')-1):
            Process(target=worker, args=(server,)).start()
    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError), e:
        logging.error('config error: %s' % e)
        return 1

    # The parent becomes a worker too
    return worker(server)


    #####   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #####


if __name__ == '__main__':
    ret = main()
    logging.shutdown()
    sys.exit(ret)

#
# EOF
#