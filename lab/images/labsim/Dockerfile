# labsim: the imitation server of the lab. Build context is lab/.
FROM golang:1.27.4-alpine AS build
WORKDIR /src
# labsim uses the standard library only, so a throwaway go.mod is enough.
RUN printf 'module github.com/iwosmu/aghpen\n\ngo 1.27\n' > go.mod
COPY labcfg ./lab/labcfg
COPY labsim ./lab/labsim
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /labsim ./lab/labsim

FROM alpine:3.24.4
RUN apk add --no-cache iptables iproute2
COPY --from=build /labsim /usr/local/bin/labsim
ENTRYPOINT ["labsim"]
