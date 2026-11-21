#!/usr/bin/perl -0p
# Makes a "second scan" from lab/defectdojo/sample-nmap.xml for the e2e check:
#   1. nginx on 172.31.250.2:80 has a new version (1.31.9 -> 1.33.0),
#   2. the Redis host 172.31.250.4 opens SSH on port 22,
#   3. Apache on 172.31.250.3:80 is closed,
#   4. the host 172.31.250.5 does not answer.
# Usage: perl deploy/e2e/modify-nmap.pl lab/defectdojo/sample-nmap.xml > second.xml
s/1\.31\.9/1.33.0/g;
s{<port protocol="tcp" portid="22"><state state="closed" reason="reset" reason_ttl="64"/><service name="ssh" method="table" conf="3"/></port>\n<port protocol="tcp" portid="80"><state state="closed"}{<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" product="OpenSSH" version="9.9" method="probed" conf="10"/></port>\n<port protocol="tcp" portid="80"><state state="closed"};
s{<state state="open" reason="syn-ack" reason_ttl="64"/><service name="http" product="Apache httpd"}{<state state="closed" reason="reset" reason_ttl="64"/><service name="http" product="Apache httpd"};
s{<status state="up" reason="localhost-response" reason_ttl="0"/>}{<status state="down" reason="no-response" reason_ttl="0"/>};
