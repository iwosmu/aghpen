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
  *)
    exec sleep infinity
    ;;
esac
