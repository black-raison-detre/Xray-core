package anytls

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/net"
)

const UoTMagic = "sp.v2.udp-over-tcp.arpa"
const (
	uotIPv4 byte = iota
	uotIPv6
	uotDomain
)

const (
	socksIPv4   byte = 1
	socksDomain byte = 3
	socksIPv6   byte = 4
)

// UoTCodec implements udp-over-tcp v2. It deliberately has no command byte:
// the first record is a connection request and subsequent records are either
// connected (length,data) or unconnected (address,length,data) datagrams.
type UoTCodec struct {
	r  io.Reader
	w  io.Writer
	mu sync.Mutex
}

func NewUoTCodec(r io.Reader, w io.Writer) *UoTCodec { return &UoTCodec{r: r, w: w} }
func (c *UoTCodec) write(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(b) > 0 {
		n, e := c.w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func writeAddress(dst net.Destination, normal bool) ([]byte, error) {
	a := dst.Address
	var b []byte
	switch a.Family() {
	case net.AddressFamilyIPv4:
		if normal {
			b = append(b, socksIPv4)
		} else {
			b = append(b, uotIPv4)
		}
		b = append(b, a.IP().To4()...)
	case net.AddressFamilyIPv6:
		if normal {
			b = append(b, socksIPv6)
		} else {
			b = append(b, uotIPv6)
		}
		b = append(b, a.IP().To16()...)
	case net.AddressFamilyDomain:
		if len(a.String()) == 0 || len(a.String()) > 255 {
			return nil, ErrMalformedFrame
		}
		if normal {
			b = append(b, socksDomain)
		} else {
			b = append(b, uotDomain)
		}
		b = append(b, byte(len(a.String())))
		b = append(b, a.String()...)
	default:
		return nil, ErrMalformedFrame
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(dst.Port))
	return append(b, p[:]...), nil
}

func readAddress(r io.Reader, normal bool) (net.Destination, error) {
	var typ [1]byte
	if _, e := io.ReadFull(r, typ[:]); e != nil {
		return net.Destination{}, e
	}
	var address net.Address
	switch typ[0] {
	case func() byte {
		if normal {
			return socksIPv4
		}
		return uotIPv4
	}():
		b := make([]byte, 4)
		if _, e := io.ReadFull(r, b); e != nil {
			return net.Destination{}, e
		}
		address = net.IPAddress(b)
	case func() byte {
		if normal {
			return socksIPv6
		}
		return uotIPv6
	}():
		b := make([]byte, 16)
		if _, e := io.ReadFull(r, b); e != nil {
			return net.Destination{}, e
		}
		address = net.IPAddress(b)
	case func() byte {
		if normal {
			return socksDomain
		}
		return uotDomain
	}():
		var n [1]byte
		if _, e := io.ReadFull(r, n[:]); e != nil {
			return net.Destination{}, e
		}
		if n[0] == 0 {
			return net.Destination{}, ErrMalformedFrame
		}
		b := make([]byte, n[0])
		if _, e := io.ReadFull(r, b); e != nil {
			return net.Destination{}, e
		}
		address = net.DomainAddress(string(b))
	default:
		return net.Destination{}, ErrMalformedFrame
	}
	var p [2]byte
	if _, e := io.ReadFull(r, p[:]); e != nil {
		return net.Destination{}, e
	}
	port := net.Port(binary.BigEndian.Uint16(p[:]))
	if normal {
		return net.TCPDestination(address, port), nil
	}
	return net.UDPDestination(address, port), nil
}

func (c *UoTCodec) WriteRequest(connected bool, destination net.Destination) error {
	a, e := writeAddress(destination, true)
	if e != nil {
		return e
	}
	b := append([]byte{0}, a...)
	if connected {
		b[0] = 1
	}
	return c.write(b)
}

func (c *UoTCodec) ReadRequest() (bool, net.Destination, error) {
	var connected [1]byte
	if _, e := io.ReadFull(c.r, connected[:]); e != nil {
		return false, net.Destination{}, e
	}
	if connected[0] > 1 {
		return false, net.Destination{}, ErrMalformedFrame
	}
	d, e := readAddress(c.r, true)
	if e == nil {
		d = net.UDPDestination(d.Address, d.Port)
	}
	return connected[0] == 1, d, e
}

func (c *UoTCodec) WriteConnected(data []byte) error {
	if len(data) > maxFrameData {
		return ErrMalformedFrame
	}
	b := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(b, uint16(len(data)))
	copy(b[2:], data)
	return c.write(b)
}

func (c *UoTCodec) ReadConnected() ([]byte, error) {
	var h [2]byte
	if _, e := io.ReadFull(c.r, h[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	b := make([]byte, n)
	_, e := io.ReadFull(c.r, b)
	return b, e
}

func (c *UoTCodec) WriteUnconnected(destination net.Destination, data []byte) error {
	if len(data) > maxFrameData {
		return ErrMalformedFrame
	}
	a, e := writeAddress(destination, false)
	if e != nil {
		return e
	}
	b := make([]byte, len(a)+2+len(data))
	copy(b, a)
	binary.BigEndian.PutUint16(b[len(a):], uint16(len(data)))
	copy(b[len(a)+2:], data)
	return c.write(b)
}

func (c *UoTCodec) ReadUnconnected() (net.Destination, []byte, error) {
	d, e := readAddress(c.r, false)
	if e != nil {
		return net.Destination{}, nil, e
	}
	b, e := c.ReadConnected()
	return d, b, e
}
