# The runtime stage of deploy/Dockerfile, with a binary built outside
# (CGO_ENABLED=0 GOOS=linux go build -tags embedui ./cmd/czujka). Build
# context: a directory that holds only that binary, named czujka.
FROM alpine:3.22
RUN apk add --no-cache nmap nmap-scripts libcap ca-certificates tzdata \
 && addgroup -S -g 10001 czujka && adduser -S -u 10001 -G czujka -h /var/lib/czujka czujka \
 && mkdir -p /var/lib/czujka && chown -R czujka:czujka /var/lib/czujka \
 && setcap cap_net_raw,cap_net_admin+eip "$(readlink -f /usr/bin/nmap)"
COPY czujka /usr/local/bin/czujka
RUN setcap cap_net_raw+ep /usr/local/bin/czujka && apk del libcap
ENV CZUJKA_LISTEN=:8080 NMAP_PRIVILEGED=1
USER czujka:czujka
WORKDIR /var/lib/czujka
ENTRYPOINT ["czujka"]
CMD ["serve"]
