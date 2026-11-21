package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// AMQPHello reads the version of an AMQP 0-9-1 broker. It sends the 8-byte
// protocol header that every AMQP client sends first ("AMQP" 0 0 9 1), reads
// the server's Connection.Start frame and closes the connection: no login,
// no other frame. nmap's -sV gets the same answer with the same header, but
// only after its NULL, GenericLines and Help probes have waited 6, 4 and
// 7.5 s on a broker that waits for a client header (22 s for RabbitMQ in the
// lab). The answer's server properties carry "product" and "version".
func AMQPHello(ctx context.Context, ip string, port int, timeout time.Duration) (product, version string, err error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", "", err
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)
	if _, err := c.Write([]byte("AMQP\x00\x00\x09\x01")); err != nil {
		return "", "", err
	}
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", "", err
	}
	if hdr[0] != 1 || binary.BigEndian.Uint16(hdr[1:3]) != 0 {
		return "", "", errors.New("amqp: not a method frame on channel 0")
	}
	size := binary.BigEndian.Uint32(hdr[3:7])
	if size < 10 || size > 64<<10 {
		return "", "", errors.New("amqp: unexpected frame size")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(c, body); err != nil {
		return "", "", err
	}
	return parseConnectionStart(body)
}

// parseConnectionStart reads product and version from the payload of a
// Connection.Start method (class 10, method 10).
func parseConnectionStart(b []byte) (product, version string, err error) {
	if len(b) < 10 || binary.BigEndian.Uint16(b[0:2]) != 10 || binary.BigEndian.Uint16(b[2:4]) != 10 {
		return "", "", errors.New("amqp: not Connection.Start")
	}
	tl := int(binary.BigEndian.Uint32(b[6:10]))
	t := b[10:]
	if tl > len(t) {
		return "", "", errors.New("amqp: short server properties")
	}
	t = t[:tl]
	for len(t) > 0 {
		n := int(t[0])
		if 1+n+1 > len(t) {
			break
		}
		name := string(t[1 : 1+n])
		typ := t[1+n]
		t = t[2+n:]
		var val string
		var skip int
		switch typ {
		case 'S', 'x', 'F', 'A':
			if len(t) < 4 {
				return product, version, nil
			}
			l := int(binary.BigEndian.Uint32(t[:4]))
			if 4+l > len(t) {
				return product, version, nil
			}
			if typ == 'S' {
				val = string(t[4 : 4+l])
			}
			skip = 4 + l
		case 't', 'b', 'B':
			skip = 1
		case 's', 'u':
			skip = 2
		case 'I', 'i', 'f':
			skip = 4
		case 'l', 'L', 'd', 'T':
			skip = 8
		case 'D':
			skip = 5
		case 'V':
			skip = 0
		default:
			return product, version, nil // unknown type: stop, keep what was read
		}
		if skip > len(t) {
			break
		}
		t = t[skip:]
		switch name {
		case "product":
			product = val
		case "version":
			version = val
		}
	}
	if product == "" {
		return "", "", errors.New("amqp: no product in server properties")
	}
	return product, version, nil
}
