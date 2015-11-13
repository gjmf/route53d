## Introduction ##

**route53d** is a DNS frontend to the [Amazon Route 53](http://aws.amazon.com/route53/) API. It allows you to use standard DNS tools to make changes to your Route 53 zones. At the moment it supports adding and deleting resource records by dynamic update (e.g with [nsupdate](http://www.oreillynet.com/linux/cmd/cmd.csp?path=n/nsupdate)).

Support for slaving from your master DNS server by incremental zone transfer (IXFR) and pushing zones changes to the API is committed but not yet well tested. Grab the [source](http://code.google.com/p/route53d/source/browse/) to try it.

## Requirements ##

  * [Python 2.6 or 2.7](http://www.python.org/)
  * [boto 2.0+](https://github.com/boto/boto)
  * [dnspython](http://www.dnspython.org/)
  * An active [Amazon Route 53](http://aws.amazon.com/route53/) account and [AWS Access Keys](http://aws.amazon.com/iam/faqs/) with access to your Route 53 service

## Installation ##

  1. Install Python, dnspython and Boto according to their documentation. [This may help](http://aws.amazon.com/articles/3998).
  1. route53d uses Boto to call the Route 53 API. [Configure Boto](http://code.google.com/p/boto/wiki/BotoConfig) with your AWS access key. There's a tutorial on the AWS blog about setting up [service-specific keys](http://aws.typepad.com/aws/2010/12/dns30-a-visual-tool-for-amazon-route-53.html) if you'd prefer not to give route53d a full-access key.
  1. Create a config file. Use route53d.ini.sample as the starting point
  1. Start the daemon: `route53d.py [--config /path/to/route53d.ini]`

## Caveats ##

At the moment there is **no authentication**. Be sure that route53d isn't reachable from untrusted sources.

The DNS dynamic update mechanism allows deletion of 1) a specific resource-record, 2) a resource-record set, or 3) deletion of all records belonging to a name. The Route 53 API implements only specific resource-record deletion so route53d will reject requests for the other deletion types.

There has been only one release of route53d because it relies on features in the development train of [boto](https://github.com/boto/boto). Until boto makes a release with their Route 53 support their APIs are still subject to change and potential breakage.