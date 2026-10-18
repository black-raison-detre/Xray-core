package shadowsocksr

import (
	"fmt"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	ssrprotocol "github.com/xtls/xray-core/proxy/shadowsocksr/internal/protocol"
)

type udpCodec struct {
	account  *MemoryAccount
	protocol ssrprotocol.IProtocol
	mu       sync.Mutex
}

func (c *udpCodec) encode(destination xnet.Destination, payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	header, err := encodeAddress(destination)
	if err != nil {
		return nil, err
	}
	plain := append(header, payload...)
	if transform, ok := c.protocol.(ssrprotocol.UDPProtocol); ok {
		plain, err = transform.UDPPreEncrypt(plain)
		if err != nil {
			return nil, err
		}
	}
	return c.account.Cipher.EncryptPacket(plain)
}

func (c *udpCodec) decode(packet []byte) (xnet.Destination, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	plain, err := c.account.Cipher.DecryptPacket(packet)
	if err != nil {
		return xnet.Destination{}, nil, err
	}
	if transform, ok := c.protocol.(ssrprotocol.UDPProtocol); ok {
		plain, err = transform.UDPPostDecrypt(plain)
		if err != nil {
			return xnet.Destination{}, nil, err
		}
	}
	dest, offset, err := decodeAddress(plain)
	if err != nil {
		return xnet.Destination{}, nil, err
	}
	return dest, append([]byte(nil), plain[offset:]...), nil
}

type udpWriter struct {
	io.Writer
	codec       *udpCodec
	destination xnet.Destination
}

func (w *udpWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		var b *buf.Buffer
		mb, b = buf.SplitFirst(mb)
		if b == nil {
			return nil
		}
		dest := w.destination
		if b.UDP != nil {
			dest = *b.UDP
		}
		packet, err := w.codec.encode(dest, b.Bytes())
		b.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		if _, err = w.Writer.Write(packet); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
}

type udpReader struct {
	io.Reader
	codec *udpCodec
}

func (r *udpReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	_, err := b.ReadFrom(r.Reader)
	if err != nil {
		b.Release()
		return nil, err
	}
	dest, payload, err := r.codec.decode(b.Bytes())
	b.Release()
	if err != nil {
		return nil, fmt.Errorf("decode ShadowsocksR UDP packet: %w", err)
	}
	out := buf.New()
	out.Write(payload)
	out.UDP = &dest
	return buf.MultiBuffer{out}, nil
}
