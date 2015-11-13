**DRAFT - Work In Progress**

# Introduction #

The `route53d` program must work within the limitations imposed by the DNS protocol and by the Amazon AWS Route 53 API. It is possible that legitimate DNS operations cannot safely be reflected in valid requests to Route 53 and `route53d` is unable to proceed. This document describes the limitations that `route53d` operates with. You must ensure that your DNS environment does not produce operations that cannot be represented to Route 53.

## Route 53 API Limits ##

Two keys limits of the Route 53 API must be respected by all Route 53 clients, including `route53d`. One API request to update DNS records:

  1. ... can change no more than one hundred records, and
  1. ... can have no more than thirty two kilobytes of record data

# Dynamic Updates #

A dynamic update is an atomic change and `route53d` will not break up a single update across multiple API calls. An update which breaks either of the Route 53 API limits will fail and no change will be enacted. The dynamic update will be responded to with a SERVFAIL opcode to signal error to the caller.

# Zone Transfer (AXFR/IXFR) #

An incremental zone transfer (IXFR) provides `route53d` a series of changes from your master DNS server. Each block of changes delimited by zone SOA serial number changes is atomic and `route53d` will not break up a single zone revision across multiple API calls. If the set of changes in any one zone revision breaks either of the Route 53 API limits it will fail and neither that change nor any subsequent change will be enacted. `route53d` will not be able to proceed with _any_ change until the zone data on Route 53 is manually brought up to a zone revision that is after the errant revision. `route53d` will emit log messages to alert you to this condition. The DNS protocol does not provide for a mechanism for an IXFR client such as `route53d` to signal an error to your master DNS server.

TBD: AXFR fallback.