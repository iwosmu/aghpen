package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func startFrame() []byte {
	var props bytes.Buffer
	field := func(name, val string) {
		props.WriteByte(byte(len(name)))
		props.WriteString(name)
		props.WriteByte('S')
		binary.Write(&props, binary.BigEndian, uint32(len(val)))
		props.WriteString(val)
	}
	// a nested table and a boolean before the strings, like RabbitMQ's capabilities
	props.WriteByte(12)
	props.WriteString("capabilities")
	props.WriteByte('F')
	binary.Write(&props, binary.BigEndian, uint32(3))
	props.Write([]byte{1, 'x', 'V'})
	field("product", "RabbitMQ")
	field("version", "4.3.8")
	field("platform", "Erlang/OTP 27")
	var p bytes.Buffer
	binary.Write(&p, binary.BigEndian, uint16(10))
	binary.Write(&p, binary.BigEndian, uint16(10))
	p.Write([]byte{0, 9})
	binary.Write(&p, binary.BigEndian, uint32(props.Len()))
	p.Write(props.Bytes())
	p.Write([]byte{0, 0, 0, 5, 'P', 'L', 'A', 'I', 'N'})
	var f bytes.Buffer
	f.WriteByte(1)
	binary.Write(&f, binary.BigEndian, uint16(0))
	binary.Write(&f, binary.BigEndian, uint32(p.Len()))
	f.Write(p.Bytes())
	f.WriteByte(0xCE)
	return f.Bytes()
}

func TestAMQPHelloReadsTheVersion(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		h := make([]byte, 8)
		io.ReadFull(c, h)
		got <- h
		c.Write(startFrame())
		io.Copy(io.Discard, c) // the client must close without sending more
	}()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(ps)
	product, version, err := AMQPHello(context.Background(), "127.0.0.1", port, 2*time.Second)
	if err != nil || product != "RabbitMQ" || version != "4.3.8" {
		t.Fatalf("product %q version %q err %v", product, version, err)
	}
	if h := <-got; string(h) != "AMQP\x00\x00\x09\x01" {
		t.Errorf("sent %q: only the protocol header is allowed", h)
	}
}

func TestAMQPHelloOnANonAMQPPort(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		c.Close()
	}()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(ps)
	if _, _, err := AMQPHello(context.Background(), "127.0.0.1", port, time.Second); err == nil {
		t.Error("want an error")
	}
}
