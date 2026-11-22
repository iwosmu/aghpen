# One "farm" of the scale lab: a real Linux TCP/IP stack that owns many
# addresses (on a dummy interface) and runs real services on them:
# nginx (80, a share with TLS on 443 and redirects), Dropbear SSH (22) and
# lighttpd (8080 on a share). nftables makes one slice answer only ICMP and
# another slice answer with closed ports only. See lab/scale/README.md.
FROM alpine:3.22
RUN apk add --no-cache nginx dropbear lighttpd openssl nftables iproute2
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
