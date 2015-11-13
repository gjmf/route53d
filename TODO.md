# TODO list #

## Started ##

<dl>
<dt>Authentication</dt>
<dd>Authenticate dynamic updates, notifies and IXFR/AXFR by TSIG. Maybe support authorization by IP address<br />Status: 70% complete.</dd>
<dt>Answer SOA queries for IXFR slave zones</dt>
<dd>Respond with the current SOA for a zone that is slaved via IXFR to allow DNS based monitoring of API update progress.<br />Status: 40% complete.</dd>
</dl>

## Not yet started ##

<dl>
<dt>Remove the deletion TTL kludge</dt>
<dd>Need to be able to populate record TTLs in API delete calls. Query from DNS? Very non-atomic ...</dd>
<dt>Use the ListHostedZones API</dt>
<dd>Call the API at startup instead of configuring each HostedZone ID in the config file. For the moment I want the script to only mess with zones that have been specifically marked as safe to play with</dd>
<dt>AXFR</dt>
<dd>An upstream server responding to IXFR can require the client to fallback to AXFR</dd>
<dt>Review the process model</dt>
<dd>It's a bit clunky. When the script internals settle down should see if there's a more appropriate way to split up the work</dd>
<dt>Cleanly handle API limits</dt>
<dd>Code for the maximum number of changes per call (1000) and maximum amount of record data (32000B) per call</dd>
<dt>Time everything</dt>
<dd>Metrics, metrics, metrics</dd>
</dl>

## Done ##

<dl>
<dt>Pending change polling</dt>
<dd>Maintain a queue of pending changes and poll the API asynchronously to log when a change is complete</dd>
</dl>