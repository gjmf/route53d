"""route53d: DNS server."""

import ConfigParser
import SocketServer
import binascii
import logging
import select
import sys
from types import IntType

import boto.route53
import boto.route53.exception
import dns.message

from libroute53d.route53 import Route53HostedZoneRequest
from libroute53d.tsig import TSIGKeyRing
from libroute53d.xfr import XFRClient


__author__ = 'James Raftery (james@now.ie)'
__vcs_id__ = '$Id$'


#noinspection PyClassicStyleClass
class UDPDNSHandler(SocketServer.BaseRequestHandler):
    """Process UDP DNS messages."""

    def handle(self):
        """Basic sanity check then handover to the opcode-specific function."""

        remote_ip = self.client_address[0]

        kr = TSIGKeyRing(remote_ip, self.server.config)

        try:
            msg = dns.message.from_wire(self.request[0], keyring=kr.keyring)
        except dns.message.BadTSIG, e:
            logging.warn('TSIG error from %s: %s' % (remote_ip, e))
            response = self.formerr(self.get_question(self.request[0]))
        except dns.message.UnknownTSIGKey, e:
            logging.warn('TSIG unknown key from %s: %s' % (remote_ip, e))
            response = self.notauth(self.get_question(self.request[0]))
        except dns.tsig.BadSignature, e:
            logging.warn('TSIG bad signature from %s: %s' % (remote_ip, e))
            response = self.notauth(self.get_question(self.request[0]))
        except dns.tsig.BadTime, e:
            logging.warn('TSIG bad time from %s: %s' % (remote_ip, e))
            response = self.notauth(self.get_question(self.request[0]))
        except Exception, e:
            logging.error('malformed message from %s: %s' % (remote_ip, e))
            logging.debug('packet: %s' % binascii.hexlify(self.request[0]))
            return
        else:
            if kr.keyring and not msg.had_tsig:
                logging.error('No TSIG from %s' % remote_ip)
                self.request[1].sendto(self.notauth(msg).to_wire(), self.client_address)
                return

            if msg.rcode() != dns.rcode.NOERROR:
                logging.warn('RCODE not NOERROR from %s' % remote_ip)
                self.request[1].sendto(self.formerr(msg).to_wire(), self.client_address)
                return

            if msg.opcode() == dns.opcode.QUERY:
                response = self.handle_query(msg)
            elif msg.opcode() == dns.opcode.NOTIFY:
                self.handle_notify(msg)
                return
            elif msg.opcode() == dns.opcode.UPDATE:
                response = self.handle_update(msg)
            else:
                logging.warn('unsupported opcode from %s: %d' % (remote_ip,
                                                                 msg.opcode()))
                response = self.notimp(msg)

        assert type(response) is dns.message.Message, \
                                    'response is not Message obj'
        if msg.had_tsig:
            response.use_tsig(keyring=kr.keyring)

        self.request[1].sendto(response.to_wire(), self.client_address)


    def handle_update(self, msg):
        """Process an update message."""

        assert type(msg) is dns.message.Message, 'msg is not Message obj'
        remote_ip = self.client_address[0]

        try:
            qname, qclass, qtype = self.parse_question(msg)
        except AssertionError:
            raise
        except Exception, e:
            logging.warn('UPDATE parse error from %s: %s' % (remote_ip, e))
            return self.servfail(msg)
        else:
            logging.info('UPDATE from %s: %s %s %s' % (remote_ip, qname,
                                    dns.rdataclass.to_text(qclass),
                                    dns.rdatatype.to_text(qtype)))

        if qtype != dns.rdatatype.SOA or qclass != dns.rdataclass.IN:
            logging.warn('UPDATE invalid question from %s' % remote_ip)
            return self.formerr(msg)

        if len(msg.answer):
            # no support for prereq's
            logging.warn('UPDATE unsupported prereqs from %s' % remote_ip)
            return self.servfail(msg)

        try:
            APIRequest = Route53HostedZoneRequest(qname, self.server.config, self.server.pending_change_q)
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            return self.notauth(msg)

        response = dns.message.make_response(msg)
        assert type(response) is dns.message.Message, \
                                    'response is not Message obj'

        if len(msg.authority) == 0:
            logging.debug('nothing to do')
            return response

        for rrset in msg.authority:
            assert type(rrset) is dns.rrset.RRset, 'rrset is not RRset obj'

            if not rrset.name.is_subdomain(qname):
                logging.warn('UPDATE NOTZONE from %s: %s %s' % (remote_ip,
                                                                qname,
                                                                rrset.name))
                response.set_rcode(dns.rcode.NOTZONE)
                return response

            if not rrset.deleting and rrset.rdclass == dns.rdataclass.IN:
                # addition
                logging.debug('UPDATE add rrset: %s' % rrset)
                if rrset.rdtype in (dns.rdatatype.ANY,  dns.rdatatype.AXFR,
                                    dns.rdatatype.IXFR, dns.rdatatype.MAILA,
                                    dns.rdatatype.MAILB):
                    logging.error('UPDATE bad rdtype from %s: %s' % \
                                                    (remote_ip, rrset))
                    response.set_rcode(dns.rcode.FORMERR)
                    return response
                else:
                    APIRequest.add(rrset)

            elif rrset.deleting == dns.rdataclass.ANY:
                # name or rrset deletion
                if rrset.ttl != 0 or \
                     rrset.rdtype in (dns.rdatatype.AXFR,  dns.rdatatype.IXFR,
                                      dns.rdatatype.MAILA, dns.rdatatype.MAILB):
                    logging.error('UPDATE illegal values from %s: %s' % \
                                                        (remote_ip, rrset))
                    response.set_rcode(dns.rcode.FORMERR)
                    return response

                logging.warn('UPDATE unsupported delete from %s: %s' % \
                                                        (remote_ip, rrset))
                response.set_rcode(dns.rcode.REFUSED)
                return response

            elif rrset.deleting == dns.rdataclass.NONE:
                # specific rr deletion
                if rrset.ttl != 0 or \
                    rrset.rdtype in (dns.rdatatype.ANY,  dns.rdatatype.AXFR,
                                     dns.rdatatype.IXFR, dns.rdatatype.MAILA,
                                     dns.rdatatype.MAILB):
                    logging.error('UPDATE illegal values from %s: %s' % \
                                                        (remote_ip, rrset))
                    response.set_rcode(dns.rcode.FORMERR)
                    return response

                # XXX TTL! Have to fake it for the moment.
                try:
                    rrset.ttl = self.server.config.getint('kludge', 'delete_ttl')
                except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
                    logging.error('no delete ttl for %s' % qname)
                    return self.servfail(msg)
                else:
                    logging.debug('found delete ttl: %d' % rrset.ttl)

                logging.debug('UPDATE delete rr: %s' % rrset)
                APIRequest.delete(rrset, fix_ttl=True)

            else:
                logging.warn('UPDATE unknown rr from %s: %s' % \
                                                    (remote_ip, rrset))
                response.set_rcode(dns.rcode.FORMERR)
                return response

        try:
            APIRequest.submit()
        except AssertionError:
            raise
        except boto.route53.exception.DNSServerError, e:
            logging.error('UPDATE API call failed: %s - %s' % \
                                        (e.code, str(e)))
            response.set_rcode(dns.rcode.SERVFAIL)
        except Exception, e:
            logging.error('UPDATE API call failed: %s' % e)
            response.set_rcode(dns.rcode.SERVFAIL)
        else:
            logging.debug('UPDATE successful')

        return response


    def handle_notify(self, msg):
        """Process an update message."""

        assert type(msg) is dns.message.Message, 'msg is not Message obj'
        remote_ip = self.client_address[0]

        try:
            qname, qclass, qtype = self.parse_question(msg)
        except AssertionError:
            raise
        except Exception, e:
            logging.warn('NOTIFY parse error from %s: %s' % (remote_ip, e))
            return self.servfail(msg)
        else:
            logging.info('NOTIFY from %s: %s %s %s' % (remote_ip, qname,
                                    dns.rdataclass.to_text(qclass),
                                    dns.rdatatype.to_text(qtype)))

        if qtype != dns.rdatatype.SOA or qclass != dns.rdataclass.IN:
            logging.warn('NOTIFY bad qclass/qtype from %s' % remote_ip)
            return self.servfail(msg)

        if not (msg.flags & dns.flags.AA):
            # BIND 8; how quaint
            logging.info('NOTIFY !AA from %s' % remote_ip)

        # Asynchronous reply
        response = dns.message.make_response(msg)
        response.flags |= dns.flags.AA
        self.request[1].sendto(response.to_wire(), self.client_address)

        try:
            xfr = XFRClient(qname, self.server.config, self.server.pending_change_q)
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            # handled in XFRClient
            return
        except (dns.query.BadResponse, dns.query.UnexpectedSource):
            # handled in XFRClient
            return
        except Exception, e:
            logging.error('XFRClient unhandled init exception: %s' % e)
            return

        try:
            xfr.parse_ixfr()
        except Exception:
            logging.exception('XFRClient unhandled parse exception')


    def handle_query(self, msg):
        """Process a query message."""

        #
        # Not ready for release yet
        #
        assert type(msg) is dns.message.Message, 'msg is not Message obj'
        remote_ip = self.client_address[0]

        try:
            qname, qclass, qtype = self.parse_question(msg)
        except AssertionError:
            raise
        except Exception, e:
            logging.warn('QUERY parse error from %s: %s' % (remote_ip, e))
            return self.servfail(msg)
        else:
            logging.info('QUERY from %s: %s %s %s' % (remote_ip, qname,
                                    dns.rdataclass.to_text(qclass),
                                    dns.rdatatype.to_text(qtype)))

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
            logging.error('missing question from %s' % remote_ip)
            raise
        else:
            assert type(n) is dns.name.Name, 'qname is not Name obj'
            assert type(c) is IntType, 'qclass is not Int obj'
            assert type(t) is IntType, 'qtype is not Int obj'
            return n, c, t


    def get_question(self, msg):
        return dns.message.from_wire(msg, question_only=True)


    # (Quasi-) One-liners for replies with common error rcodes
    def servfail(self, msg):
        msg = dns.message.make_response(msg)
        msg.set_rcode(dns.rcode.SERVFAIL)
        return msg

    def notimp(self, msg):
        msg = dns.message.make_response(msg)
        msg.set_rcode(dns.rcode.NOTIMP)
        return msg

    def formerr(self, msg):
        msg = dns.message.make_response(msg)
        msg.set_rcode(dns.rcode.FORMERR)
        return msg

    def notauth(self, msg):
        msg = dns.message.make_response(msg)
        msg.set_rcode(dns.rcode.NOTAUTH)
        return msg


def worker(server):
    """Worker loop.

    Jumping to a signal handler can yield harmless select.error exceptions.
    Catch them and reattach to the socket.

    """

    logging.debug('Starting worker')
    while True:
        try:
            server.serve_forever()
        except select.error:
            # ignore the interrupted syscall spew if we catch a signal
            pass
        except KeyboardInterrupt:
            break
        except AssertionError:
            raise
        except Exception, e:
            logging.error('Exiting. Caught exception %s' % e)
            return 1

    logging.info('Exiting.')
    return 0


def bind_socket(config):
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