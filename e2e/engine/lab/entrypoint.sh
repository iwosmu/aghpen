#!/bin/sh
# Roles of the lab image. ROLE and PORT come from the environment.
set -e
PORT="${PORT:-80}"
case "${ROLE:-idle}" in
  ssh)
    ssh-keygen -A >/dev/null
    exec /usr/sbin/sshd -D -e
    ;;
  http)
    exec python3 -m http.server "$PORT" --directory /srv/www
    ;;
  https)
    exec python3 -c "
import http.server, ssl, functools
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory='/srv/www')
s = http.server.ThreadingHTTPServer(('0.0.0.0', $PORT), h)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain('/srv/cert.pem', '/srv/key.pem')
s.socket = c.wrap_socket(s.socket, server_side=True)
s.serve_forever()"
    ;;
  noicmp)
    # This host drops every ICMP packet. It still serves HTTP.
    iptables -A INPUT -p icmp -j DROP 2>/dev/null || iptables-legacy -A INPUT -p icmp -j DROP
    exec python3 -m http.server "$PORT" --directory /srv/www
    ;;
  udp)
    # UDP services for the optional UDP scan: DNS on 53 and NTP on 123.
    ntpd -l 2>/dev/null || true
    # an SNMP agent with an empty configuration: it answers the SNMPv3 engine
    # discovery and gives no data to anyone
    snmpd -C -c /dev/null udp:161 2>/dev/null || true
    exec dnsmasq -k --no-resolv --no-hosts --address=/lab.test/10.76.0.70
    ;;
  router)
    # Forwards between the scanner network and the lab and hides the scanner
    # behind its own lab address.
    iptables -t nat -A POSTROUTING -s 10.78.0.0/24 -d 10.77.0.0/22 -j MASQUERADE 2>/dev/null \
      || iptables-legacy -t nat -A POSTROUTING -s 10.78.0.0/24 -d 10.77.0.0/22 -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 10.78.0.0/24 -d 10.79.0.0/20 -j MASQUERADE 2>/dev/null \
      || iptables-legacy -t nat -A POSTROUTING -s 10.78.0.0/24 -d 10.79.0.0/20 -j MASQUERADE
    exec sleep infinity
    ;;
  *)
    exec sleep infinity
    ;;
esac
