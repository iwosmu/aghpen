# Scanner box: a small container on the lab network for manual checks.
FROM alpine:3.24.4
RUN apk add --no-cache nmap nmap-scripts nmap-nselibs curl bind-tools jq openssl iproute2
WORKDIR /work
CMD ["sleep", "infinity"]
