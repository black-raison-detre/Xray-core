package websocket_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	xraywebsocket "github.com/xtls/xray-core/transport/internet/websocket"
)

func TestConnectionReadCloseFramesAndDisconnect(t *testing.T) {
	const payload = "queued WebSocket payload"
	tests := []struct {
		name            string
		closeCode       int
		abrupt          bool
		wantEOF         bool
		wantCloseCode   int
		wantNonEOFError bool
	}{
		{name: "normal close", closeCode: websocket.CloseNormalClosure, wantEOF: true},
		{name: "no status", closeCode: websocket.CloseNoStatusReceived, wantEOF: true},
		{name: "policy close", closeCode: websocket.ClosePolicyViolation, wantCloseCode: websocket.ClosePolicyViolation},
		{name: "abrupt disconnect", abrupt: true, wantNonEOFError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				peer, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				if err := peer.WriteMessage(websocket.BinaryMessage, []byte(payload)); err != nil {
					_ = peer.Close()
					return
				}
				if test.abrupt {
					_ = peer.UnderlyingConn().Close()
					return
				}
				_ = peer.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(test.closeCode, ""),
					time.Now().Add(time.Second),
				)
				_ = peer.Close()
			}))
			defer server.Close()

			client, _, err := websocket.DefaultDialer.Dial(strings.Replace(server.URL, "http://", "ws://", 1), nil)
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			conn := xraywebsocket.NewConnection(client, client.RemoteAddr(), nil, 0)
			defer conn.Close()
			if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline() error = %v", err)
			}

			gotPayload, readErr := readConnectionToError(conn)
			if string(gotPayload) != payload {
				t.Fatalf("Read() payload = %q, want %q (terminal error: %v)", gotPayload, payload, readErr)
			}

			switch {
			case test.wantEOF && readErr != io.EOF:
				t.Fatalf("Read() terminal error = %v, want io.EOF", readErr)
			case test.wantCloseCode != 0:
				var closeErr *websocket.CloseError
				if !errors.As(readErr, &closeErr) || closeErr.Code != test.wantCloseCode {
					t.Fatalf("Read() terminal error = %v, want WebSocket close code %d", readErr, test.wantCloseCode)
				}
			case test.wantNonEOFError && (readErr == nil || errors.Is(readErr, io.EOF)):
				t.Fatalf("Read() terminal error = %v, want non-EOF error for abrupt disconnect", readErr)
			}
		})
	}
}

func readConnectionToError(conn interface {
	Read([]byte) (int, error)
},
) ([]byte, error) {
	buffer := make([]byte, 4)
	var payload []byte
	for {
		n, err := conn.Read(buffer)
		payload = append(payload, buffer[:n]...)
		if err != nil {
			return payload, err
		}
		if n == 0 {
			return payload, io.ErrNoProgress
		}
	}
}
