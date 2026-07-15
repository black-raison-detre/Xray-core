package shadowsocksr

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/obfs"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/ssr"
)

const maxSessionBuffer = 256 * 1024

type sessionConn struct {
	stdnet.Conn
	account              *MemoryAccount
	protocol             protocol.IProtocol
	obfs                 obfs.IObfs
	writeMu              sync.Mutex
	globalMu             *sync.Mutex
	readMu               sync.Mutex
	header               []byte
	headerSent           bool
	sendIV               []byte
	recvIV               []byte
	encryptor, decryptor interface{ XORKeyStream(dst, src []byte) }
	protocolBuffer       bytes.Buffer
	plainBuffer          bytes.Buffer
}

func newSessionConn(conn stdnet.Conn, account *MemoryAccount, server xnet.Destination, target xnet.Destination, protocolData, obfsData interface{}, globalMu *sync.Mutex) (*sessionConn, error) {
	p := protocol.NewProtocol(account.Protocol)
	o := obfs.NewObfs(account.Obfs)
	if p == nil || o == nil {
		return nil, fmt.Errorf("unsupported ShadowsocksR protocol or obfs")
	}
	header, err := encodeAddress(target)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, account.Cipher.Method().IVSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generate ShadowsocksR IV: %w", err)
	}
	info := &ssr.ServerInfo{
		Host: server.Address.String(), Port: uint16(server.Port), Param: string(account.ProtocolParam),
		IV: iv, IVLen: len(iv), Key: account.Cipher.Key(), KeyLen: len(account.Cipher.Key()),
		HeadLen: len(header), TcpMss: 1460, Random: rand.Reader, Now: time.Now,
	}
	info.Overhead = p.GetOverhead() + o.GetOverhead()
	p.SetServerInfo(info)
	p.SetData(protocolData)
	obfsInfo := *info
	obfsInfo.Param = string(account.ObfsParam)
	o.SetServerInfo(&obfsInfo)
	o.SetData(obfsData)
	stream, err := account.Cipher.NewEncrypter(iv)
	if err != nil {
		return nil, err
	}
	return &sessionConn{Conn: conn, account: account, protocol: p, obfs: o, header: header, sendIV: iv, encryptor: stream, globalMu: globalMu}, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (c *sessionConn) writeObfs(data []byte) error {
	encoded, err := c.obfs.Encode(data)
	if err != nil {
		return err
	}
	return writeAll(c.Conn, encoded)
}

func (c *sessionConn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(data) == 0 {
		return 0, c.writeObfs(nil)
	}
	plain := data
	if !c.headerSent {
		plain = append(append([]byte(nil), c.header...), data...)
		c.headerSent = true
		if c.globalMu != nil {
			c.globalMu.Lock()
			defer c.globalMu.Unlock()
		}
	}
	framed, err := c.protocol.PreEncrypt(plain)
	if err != nil {
		return 0, err
	}
	encrypted := make([]byte, len(framed))
	c.encryptor.XORKeyStream(encrypted, framed)
	if c.sendIV != nil {
		encrypted = append(append([]byte(nil), c.sendIV...), encrypted...)
		c.sendIV = nil
	}
	if err := c.writeObfs(encrypted); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *sessionConn) sendBack() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeObfs(nil)
}

func (c *sessionConn) Read(dst []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.plainBuffer.Len() > 0 {
			return c.plainBuffer.Read(dst)
		}
		wire := make([]byte, 32*1024)
		n, err := c.Conn.Read(wire)
		if n > 0 {
			decoded, sendBack, decodeErr := c.obfs.Decode(wire[:n])
			if decodeErr != nil {
				return 0, decodeErr
			}
			if sendBack {
				if e := c.sendBack(); e != nil {
					return 0, e
				}
			}
			if len(decoded) > 0 {
				if c.decryptor == nil {
					ivLen := c.account.Cipher.Method().IVSize
					need := ivLen - len(c.recvIV)
					if need > len(decoded) {
						need = len(decoded)
					}
					c.recvIV = append(c.recvIV, decoded[:need]...)
					decoded = decoded[need:]
					if len(c.recvIV) == ivLen {
						c.decryptor, decodeErr = c.account.Cipher.NewDecrypter(c.recvIV)
						if decodeErr != nil {
							return 0, decodeErr
						}
					}
				}
				if c.decryptor != nil && len(decoded) > 0 {
					plain := make([]byte, len(decoded))
					c.decryptor.XORKeyStream(plain, decoded)
					if c.protocolBuffer.Len()+len(plain) > maxSessionBuffer {
						return 0, fmt.Errorf("ShadowsocksR protocol buffer exceeds %d bytes", maxSessionBuffer)
					}
					c.protocolBuffer.Write(plain)
					out, consumed, e := c.protocol.PostDecrypt(c.protocolBuffer.Bytes())
					if e != nil {
						return 0, e
					}
					if consumed < 0 || consumed > c.protocolBuffer.Len() {
						return 0, fmt.Errorf("ShadowsocksR protocol returned invalid consumption %d", consumed)
					}
					c.protocolBuffer.Next(consumed)
					c.plainBuffer.Write(out)
				}
			}
			if c.plainBuffer.Len() > 0 {
				return c.plainBuffer.Read(dst)
			}
		}
		if err != nil {
			return 0, err
		}
	}
}

func encodeAddress(destination xnet.Destination) ([]byte, error) {
	var out []byte
	switch destination.Address.Family() {
	case xnet.AddressFamilyIPv4:
		out = append(out, 1)
		out = append(out, destination.Address.IP()...)
	case xnet.AddressFamilyIPv6:
		out = append(out, 4)
		out = append(out, destination.Address.IP()...)
	case xnet.AddressFamilyDomain:
		domain := destination.Address.Domain()
		if len(domain) > 255 {
			return nil, fmt.Errorf("destination domain is too long")
		}
		out = append(out, 3, byte(len(domain)))
		out = append(out, domain...)
	default:
		return nil, fmt.Errorf("invalid destination address")
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(destination.Port))
	out = append(out, port[:]...)
	return out, nil
}

func decodeAddress(data []byte) (xnet.Destination, int, error) {
	if len(data) < 1 {
		return xnet.Destination{}, 0, io.ErrUnexpectedEOF
	}
	var address xnet.Address
	offset := 1
	switch data[0] & 0x0f {
	case 1:
		if len(data) < 7 {
			return xnet.Destination{}, 0, io.ErrUnexpectedEOF
		}
		address = xnet.IPAddress(data[1:5])
		offset = 5
	case 4:
		if len(data) < 19 {
			return xnet.Destination{}, 0, io.ErrUnexpectedEOF
		}
		address = xnet.IPAddress(data[1:17])
		offset = 17
	case 3:
		if len(data) < 2 {
			return xnet.Destination{}, 0, io.ErrUnexpectedEOF
		}
		n := int(data[1])
		if len(data) < n+4 {
			return xnet.Destination{}, 0, io.ErrUnexpectedEOF
		}
		address = xnet.DomainAddress(string(data[2 : 2+n]))
		offset = 2 + n
	default:
		return xnet.Destination{}, 0, fmt.Errorf("invalid ShadowsocksR address type %d", data[0])
	}
	port := xnet.Port(binary.BigEndian.Uint16(data[offset : offset+2]))
	return xnet.UDPDestination(address, port), offset + 2, nil
}
