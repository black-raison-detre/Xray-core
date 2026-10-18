package obfs

import (
	"bytes"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/ssr"
)

func obfsInfo() *ssr.ServerInfo {
	return &ssr.ServerInfo{Host: "example.com", Port: 443, Param: "a.example,b.example", IV: bytes.Repeat([]byte{1}, 16), IVLen: 16, Key: bytes.Repeat([]byte{2}, 32), KeyLen: 32, HeadLen: 7, TcpMss: 1460, Random: bytes.NewReader(bytes.Repeat([]byte{3}, 1<<20)), Now: func() time.Time { return time.Unix(1700000000, 0) }}
}

func TestActiveObfsRegistry(t *testing.T) {
	for _, name := range []string{"plain", "http_simple", "http_post", "tls1.2_ticket_auth"} {
		if NewObfs(name) == nil {
			t.Fatalf("obfs %q is not registered", name)
		}
	}
}

func TestHTTPResponseFragmentBuffering(t *testing.T) {
	o := NewObfs("http_simple")
	o.SetServerInfo(obfsInfo())
	for _, fragment := range [][]byte{[]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r"), []byte("\n\r"), []byte("\nabc")} {
		out, _, err := o.Decode(fragment)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) > 0 && string(out) != "abc" {
			t.Fatalf("unexpected payload %q", out)
		}
	}
}

func FuzzObfsDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("HTTP/1.1 200 OK\r\n\r\nbody"))
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		for _, name := range []string{"plain", "http_simple", "http_post", "tls1.2_ticket_auth"} {
			o := NewObfs(name)
			o.SetServerInfo(obfsInfo())
			o.SetData(o.GetData())
			_, _, _ = o.Decode(data)
		}
	})
}
