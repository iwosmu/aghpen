# Lab image for the engine end-to-end check. One image, several roles
# (see entrypoint.sh). It also carries nmap, so the scanner container uses it too.
FROM alpine:3.20
RUN apk add --no-cache nmap nmap-nselibs nmap-scripts openssh-server python3 iptables openssl libcap dnsmasq \
 && mkdir -p /srv/www /run/sshd \
 && openssl req -x509 -newkey rsa:2048 -nodes -keyout /srv/key.pem -out /srv/cert.pem -days 30 -subj "/CN=czeng-lab.test/O=Czujka lab" 2>/dev/null \
 && echo '<html><head><title>Czujka lab</title></head><body>lab host</body></html>' > /srv/www/index.html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
