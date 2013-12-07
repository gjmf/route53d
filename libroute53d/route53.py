"""route53d: Amazon Route 53 interface."""

import ConfigParser
from Queue import Full, Empty
import logging
import time
from types import StringType

import dns.rdatatype
import dns.name
import dns.rrset
import dns.rdataclass


import boto.route53
import boto.route53.record
import boto.route53.exception


__author__ = 'James Raftery (james@now.ie)'
__vcs_id__ = '$Id$'


class Route53HostedZoneRequest(object):

    def __init__(self, zonename, config, pending_change_q):
        assert type(zonename) is dns.name.Name, 'zonename is not Name obj'
        self.zonename = zonename
        self.pending_change_q = pending_change_q

        try:
            self.zoneid = config.get('hostedzone',
                                     self.zonename.to_text())
        except ConfigParser.NoSectionError:
            logging.error('no zoneid for %s' % self.zonename)
            raise
        except ConfigParser.NoOptionError:
            try:
                self.zoneid = config.get('hostedzone',
                                         self.zonename.to_text(omit_final_dot=True))
            except ConfigParser.NoOptionError:
                logging.error('no zoneid for %s' % self.zonename)
                raise
        else:
            logging.debug('found %s zoneid: %s' % (self.zonename, self.zoneid))

        try:
            self.dryrun = config.getint('server', 'dry-run')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            self.dryrun = False


        assert type(self.zoneid) is StringType, 'zoneid is not String obj'
        self.r = boto.route53.record.ResourceRecordSets(hosted_zone_id=self.zoneid)
        self.changequeue = dict()

    # TODO
    #  Max of 1000 ResourceRecord elements
    #  Max of 32000 characters in record data
    #

    def add(self, rrset):
        logging.debug('additions: %s' % rrset)
        if dns.rdatatype.is_singleton(rrset.rdtype):
            self._enqueue_change('CREATE', rrset)
            return

        current_rrset = self.get_record_set(rrset.name, rrset.rdtype)
        logging.debug('current set: %s' % current_rrset)
        if current_rrset is None:
            self._enqueue_change('CREATE', rrset)
            return

        self._enqueue_change('DELETE', current_rrset)
        current_rrset.union_update(rrset)
        if len(current_rrset):
            self._enqueue_change('CREATE', current_rrset)

    def delete(self, rrset, fix_ttl=False):
        logging.debug('deletions: %s' % rrset)
        if dns.rdatatype.is_singleton(rrset.rdtype):
            if fix_ttl:
                # XXX what if not found
                current_rrset = self.get_record_set(rrset.name, rrset.rdtype)
                logging.debug('setting TTL: %d' % current_rrset.ttl)
                rrset.ttl = current_rrset.ttl
            self._enqueue_change('DELETE', rrset)
            return

        # XXX what if not found
        current_rrset = self.get_record_set(rrset.name, rrset.rdtype)
        logging.debug('current set: %s' % current_rrset)

        if fix_ttl:
            logging.debug('setting TTL: %d' % current_rrset.ttl)
            rrset.ttl = current_rrset.ttl

        if current_rrset is None:
            # XXX how did this happen?!
            self._enqueue_change('DELETE', rrset)
            return

        self._enqueue_change('DELETE', current_rrset)
        current_rrset.difference_update(rrset)
        if len(current_rrset):
            self._enqueue_change('CREATE', current_rrset)

    def _enqueue_change(self, action, rrset):
        if action not in ('CREATE', 'DELETE'):
            raise RuntimeError()
        assert type(rrset) is dns.rrset.RRset, 'rrset is not RRset obj: %s' % type(rrset)
        logging.debug('%s %s' % (action, rrset))

        try:
            change = self.changequeue[(rrset.name.to_text().lower(),rrset.rdtype,action)]
        except KeyError:
            change = self.r.add_change(action, rrset.name,
                                       dns.rdatatype.to_text(rrset.rdtype),
                                       rrset.ttl)
            self.changequeue[(rrset.name.to_text().lower(),rrset.rdtype,action)] = change

        for rdata in rrset:
            change.add_value(rdata)

    def get_record_set(self, qname, qtype):

        if isinstance(qtype, int):
            qtype = dns.rdatatype.to_text(qtype)

        logging.debug('get %s %s %s %s' % (qname, type(qname), qtype, type(qtype)))
        cnxn = boto.route53.Route53Connection()
        # result is a boto.route53.record.ResourceRecordSets object
        result = cnxn.get_all_rrsets(self.zoneid, type=qtype, name=qname, maxitems=1)

        rdatas = list()
        # rrset is a boto.route53.record.Record object
        for rrset in result:
            logging.debug('got %s %s' % (rrset.name, rrset.type))
            if rrset.name == qname.to_text() and rrset.type == qtype:
                logging.debug('populating %s %s' % (rrset.name, rrset.type))
                for rr in rrset.resource_records:
                    rdatas.append(str(rr))
            if result.is_truncated and (result.next_record_name != qname.to_text()
                    or result.next.record_type != qtype):
                break

        logging.debug('%s %s rdatas: %s' % (qname, qtype, ','.join(rdatas)))

        if len(rdatas) == 0:
            return None
        else:
            return dns.rrset.from_text_list(qname, int(result[0].ttl),
                                            dns.rdataclass.IN, qtype, rdatas)

    def submit(self, serial=None):

        # XXX - use the serial/comment

        if self.dryrun:
            logging.debug('Dry-run. No change submitted')
            return

        result = self.r.commit()
        logging.debug(result)
        self.r = boto.route53.record.ResourceRecordSets(hosted_zone_id=self.zoneid)
        self.changequeue = dict()

        try:
            info = result.get('ChangeResourceRecordSetsResponse').get('ChangeInfo')
        except KeyError:
            # XXX need to parse error response
            logging.error('invalid response: %s' % result)
            raise
        else:
            change_id = info.get('Id').lstrip('/change/')
            status = info.get('Status')
            logging.info('ChangeID: %s Status: %s' % (change_id, status))
            if status == 'PENDING':
                try:
                    self.pending_change_q.put(change_id)
                except Full:
                    logging.warn('status poller queue full, '
                                 'discarding change %s' % change_id)


def status_poller(q):
    """Take change IDs from the global queue and poll the API for them until
       they're INSYNC

    """

    logging.debug('Starting status poller')
    cnxn = boto.route53.Route53Connection()

    while True:
        try:
            change_id = q.get_nowait()
        except Empty:
            logging.debug('queue is empty')
        else:
            # XXX catch exceptions!
            result = cnxn.get_change(change_id)
            logging.debug(result)

            try:
                info = result.get('GetChangeResponse').get('ChangeInfo')
            except KeyError:
                # XXX need to parse error response
                logging.error('invalid response: %s' % result)
                raise
            else:
                status = info.get('Status')
                logging.info('ChangeID: %s Status: %s' % (change_id, status))
                if status == 'PENDING':
                    try:
                        q.put(change_id)
                    except Full:
                        logging.warn('status poller queue full, '
                                     'discarding change %s' % change_id)
        finally:
            time.sleep(2)