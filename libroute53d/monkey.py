
"""route53d: Monkey patching."""


import struct
import time

import dns.rdataclass
import dns.rdatatype
import dns.message
import dns.name
import dns.edns
import dns.tsig


__author__ = 'James Raftery (james@now.ie)'
__vcs_id__ = '$Id$'


def monkey_patch_all():
    """Perform all monkey patching for route53d."""
    monkey_patch_dnspython()


def monkey_patch_dnspython():
    """Monkey patch DNSPython."""
    monkey_patch_dnspython_wirereader()


def monkey_patch_dnspython_wirereader():
    """Monkey patch the DNSPython WireReader class.

    This is a modified version of _WireReader._get_section from dnspython
    1.9.2. It fixes a section comparison bug and always decodes record RDATA
    in Update messages.

    """

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
                    raise dns.message.BadEDNS()
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
                    raise dns.message.BadTSIG()
                if self.message.keyring is None:
                    raise dns.message.UnknownTSIGKey('got signed message without keyring')
                secret = self.message.keyring.get(absolute_name)
                if secret is None:
                    raise dns.message.UnknownTSIGKey("key '%s' unknown" % name)
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
                    rdclass = self.zone_rdclass
                else:
                    deleting = None

                rd = dns.rdata.from_wire(rdclass, rdtype, self.wire,
                                         self.current, rdlen,
                                         self.message.origin)

                if deleting == dns.rdataclass.ANY or \
                        (deleting == dns.rdataclass.NONE and
                                 section is self.message.answer):
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
