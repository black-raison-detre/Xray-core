package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type tunnelTestDialer struct {
	conn net.Conn
}

func (d tunnelTestDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return d.conn, nil
}

func (tunnelTestDialer) DestIpAddress() net.IP { return nil }

func (tunnelTestDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func TestHTTP1TunnelKeepsDataReadWithResponse(t *testing.T) {
	for _, greeting := range []string{"", "220 smtp ready\r\n"} {
		t.Run(fmt.Sprintf("greeting=%q", greeting), func(t *testing.T) {
			client, server := stdnet.Pipe()
			defer client.Close()
			defer server.Close()
			deadline := time.Now().Add(5 * time.Second)
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := server.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}

			const tail = "250 next response\r\n"
			serverDone := make(chan error, 1)
			go func() {
				defer server.Close()
				req, err := http.ReadRequest(bufio.NewReader(server))
				if err == nil && req.Method != http.MethodConnect {
					err = fmt.Errorf("unexpected method: %s", req.Method)
				}
				if err == nil {
					// net.Pipe delivers this whole write to the CONNECT response
					// reader, deterministically buffering the greeting with it.
					_, err = io.WriteString(server, "HTTP/1.1 200 Connection established\r\n\r\n"+greeting)
				}
				if err == nil {
					_, err = io.WriteString(server, tail)
				}
				serverDone <- err
			}()

			dest := net.TCPDestination(net.LocalHostIP, 8080)
			conn, err := setUpHTTPTunnel(context.Background(), dest, "example.com:25", nil, tunnelTestDialer{conn: client}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			// Small reads must drain the greeting and then resume the raw stream.
			var got []byte
			chunk := make([]byte, 3)
			for {
				n, err := conn.Read(chunk)
				got = append(got, chunk[:n]...)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if want := greeting + tail; string(got) != want {
				t.Fatalf("tunnel data = %q, want %q", got, want)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
