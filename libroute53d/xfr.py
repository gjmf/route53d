"""route53d: DNS AXFR/IXFR client."""

import ConfigParser
import logging
import socket
from types import MethodType
import dns.rrset
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.exception
import dns.tsig
import dns.query
import boto.route53
import boto.route53.exception
from libroute53d.exceptions import EndOfDataException
from libroute53d.route53 import Route53HostedZoneRequest
from libroute53d.tsig import TSIGKeyRing


__author__ = 'James Raftery (james@now.ie)'
__vcs_id__ = '$Id$'


class XFRClient(object):

    def __init__(self, zonename, config, pending_change_q):

        assert type(zonename) is dns.name.Name, 'zonename is not Name obj'
        self.zonename = zonename
        self.local_serial = None
        self.remote_serial = None
        self.masterip = None
        self.doit = None
        self.rrsetcount = 0
        self.markers = 0

        try:
            self.APIRequest = Route53HostedZoneRequest(self.zonename, config, pending_change_q)
        except Exception, e:
            logging.debug('exception: %s' % e)
            raise

        try:
            self.zoneid = config.get('hostedzone',
                                     zonename.to_text())
        except ConfigParser.NoSectionError:
            logging.error('no zoneid for %s' % zonename)
            raise
        except ConfigParser.NoOptionError:
            try:
                self.zoneid = config.get('hostedzone',
                                         zonename.to_text(omit_final_dot=True))
            except ConfigParser.NoOptionError:
                logging.error('no zoneid for %s' % zonename)
                raise
        else:
            logging.debug('found %s zoneid: %s' % (zonename, self.zoneid))

        self.cnxn = boto.route53.Route53Connection()
        # result is a boto.route53.record.ResourceRecordSets object
        result = self.cnxn.get_all_rrsets(self.zoneid, type='SOA', maxitems=1,
                                          name=zonename.to_text())
        if len(result) != 1:
            raise RuntimeError('uh-oh')

        # rr is a boto.route53.record.Record object
        rr = result[0]
        if rr.type == 'SOA':
            rrset = dns.rrset.from_text(zonename, rr.ttl,
                                        dns.rdataclass.IN, dns.rdatatype.SOA,
                                        str(rr.resource_records[0]))
        else:
            raise RuntimeError()

        logging.info('API serial for %s: %s' % (zonename, rrset[0].serial))
        self.local_serial = rrset[0].serial

        try:
            self.masterip = config.get('slave',
                                       self.zonename.to_text())
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            # XXX
            logging.error('no master ip for %s' % self.zonename)
            raise

        kr = TSIGKeyRing(self.masterip, config)

        try:
            logging.debug('xfr %s %s %d' % (self.masterip, self.zonename,
                                            self.local_serial))
            # XXX Argh. xfr() requires a keyname
            self.msgs = dns.query.xfr(self.masterip, self.zonename,
                            serial=self.local_serial, relativize=False,
                            rdtype=dns.rdatatype.IXFR,
                            keyring=kr.keyring, keyname=kr.keyname)
        except (dns.query.BadResponse, dns.query.UnexpectedSource), e:
            logging.error('XFR failed: %s %s' % (self.zonename, e))
            raise


    def parse_soa(self, rrset):
        assert type(rrset) is dns.rrset.RRset, 'rrset is RRset obj'
        assert rrset.rdtype == dns.rdatatype.SOA, 'rrset is not SOA RRset'
        self.markers += 1   # count of ixfr zone increment markers
        logging.debug('markers: %s serial %d' % (self.markers, rrset[0].serial))

        if self.markers % 2 == 0:
            # start of an addition block
            self.doit = self.APIRequest.add
        else:
            # start of deletion block
            self.doit = self.APIRequest.delete
            if rrset[0].serial != self.local_serial:
                try:
                    # XXX - save SOA to RR cache
                    self.APIRequest.submit(serial=rrset[0].serial)
                except AssertionError:
                    raise
                except boto.route53.exception.DNSServerError, e:
                    logging.error('XFR API call failed: %s - %s' % \
                                  (e.code, str(e)))
                    raise
                except Exception, e:
                    logging.error('XFR API call failed: %s' % e)
                    raise
                else:
                    logging.debug('XFR stage, %s serial %d' % \
                                    (self.zonename, rrset[0].serial))

            if rrset[0].serial == self.remote_serial:
                logging.info('XFR successful, %s serial %d' % \
                                        (self.zonename, rrset[0].serial))
                raise EndOfDataException


    def parse_ixfr(self):
        try:
          for msg in self.msgs:
            for rrset in msg.answer:
                self.rrsetcount += 1
                logging.debug('RR %d: %s' % (self.rrsetcount, rrset))

                if self.rrsetcount == 1:
                    if rrset[0].rdtype != dns.rdatatype.SOA:
                        logging.error('protocol error: %s' % rrset)
                        return
                    else:
                        self.remote_serial = rrset[0].serial
                        logging.debug('remote_serial: %d' % self.remote_serial)
                        continue

                if self.rrsetcount == 2:
                    if rrset[0].rdtype != dns.rdatatype.SOA or \
                            rrset[0].serial != self.local_serial:
                        logging.error('protocol error: %s' % rrset)
                        return

                if rrset[0].rdtype == dns.rdatatype.SOA:
                    try:
                        self.parse_soa(rrset)
                    except EndOfDataException:
                        assert self.rrsetcount == len(msg.answer), \
                                                        'unprocessed RRs'
                        return
                    except boto.route53.exception.DNSServerError:
                        return
                    except Exception:
                        raise

                assert type(self.doit) is MethodType, 'doit is not method'
                self.doit(rrset)
        except dns.exception.FormError, e:
            logging.error('malformed message from %s: %s' % (self.masterip, e))
            # XXX
            return
        except socket.error, e:
            logging.error('socket error from %s: %s' % (self.masterip, e))
            # XXX
            return
        except dns.tsig.PeerBadKey, e:
            logging.error('TSIG bad key from %s: %s' % (self.masterip, e))
            return
        except dns.tsig.PeerBadSignature, e:
            logging.error('TSIG bad sig from %s: %s' % (self.masterip, e))
            return
        except dns.tsig.PeerBadTime, e:
            logging.error('TSIG bad time from %s: %s' % (self.masterip, e))
            return
        except dns.tsig.PeerBadTruncation, e:
            logging.error('TSIG bad truncation from %s: %s' % (self.masterip, e))
            return

        if self.rrsetcount == 1:
            # XXX  remote_serial == local_serial means no update needed
            logging.warn('one SOA rr - AXFR fallback')



