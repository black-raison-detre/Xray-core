package packetstack

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

type packet struct {
	data []byte
	dest *net.Destination
}
type udpConnectionHandler struct {
	sync.RWMutex
	udpConns         map[net.Destination]*udpConn
	handleConnection func(net.Conn, net.Destination)
	writePacket      func([]byte, net.Destination, net.Destination) error
}

func newUDPConnectionHandler(handleConnection func(net.Conn, net.Destination), writePacket func([]byte, net.Destination, net.Destination) error) *udpConnectionHandler {
	return &udpConnectionHandler{udpConns: make(map[net.Destination]*udpConn), handleConnection: handleConnection, writePacket: writePacket}
}

func (u *udpConnectionHandler) HandlePacket(src, dst net.Destination, data []byte) {
	u.RLock()
	conn, found := u.udpConns[src]
	if found {
		select {
		case conn.egress <- &packet{data: data, dest: &dst}:
		default:
			errors.LogDebug(context.Background(), "drop udp with size ", len(data), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full")
		}
		u.RUnlock()
		return
	}
	u.RUnlock()
	u.Lock()
	defer u.Unlock()
	conn, found = u.udpConns[src]
	if !found {
		conn = &udpConn{handler: u, egress: make(chan *packet, 1024), src: src, dst: dst}
		u.udpConns[src] = conn
		go u.handleConnection(conn, dst)
	}
	select {
	case conn.egress <- &packet{data: data, dest: &dst}:
	default:
		errors.LogDebug(context.Background(), "drop udp with size ", len(data), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full")
	}
}

func (u *udpConnectionHandler) connectionFinished(src net.Destination) {
	u.Lock()
	if conn, found := u.udpConns[src]; found {
		delete(u.udpConns, src)
		close(conn.egress)
	}
	u.Unlock()
}

type udpConn struct {
	handler  *udpConnectionHandler
	egress   chan *packet
	src, dst net.Destination
}

func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		e, ok := <-c.egress
		if !ok {
			return nil, io.EOF
		}
		b := buf.New()
		if _, err := b.Write(e.data); err != nil {
			errors.LogErrorInner(context.Background(), err, "drop packet to ", e.dest, " with size ", len(e.data))
			b.Release()
			continue
		}
		b.UDP = e.dest
		return buf.MultiBuffer{b}, nil
	}
}

func (c *udpConn) Read(p []byte) (int, error) {
	e, ok := <-c.egress
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, e.data)
	if n != len(e.data) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.dst
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				errors.LogError(context.Background(), "impossible domain packet ", b.UDP, " reply via original target ", dst)
			} else {
				dst = *b.UDP
			}
		}
		if err := c.handler.writePacket(b.Bytes(), dst, c.src); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

func (c *udpConn) Write(p []byte) (int, error) {
	if err := c.handler.writePacket(p, c.dst, c.src); err != nil {
		return 0, nil
	}
	return len(p), nil
}

func (c *udpConn) Close() error                     { c.handler.connectionFinished(c.src); return nil }
func (c *udpConn) LocalAddr() net.Addr              { return c.dst.RawNetAddr() }
func (c *udpConn) RemoteAddr() net.Addr             { return c.src.RawNetAddr() }
func (c *udpConn) SetDeadline(time.Time) error      { return nil }
func (c *udpConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpConn) SetWriteDeadline(time.Time) error { return nil }
