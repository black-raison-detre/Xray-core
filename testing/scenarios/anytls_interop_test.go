package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/anytls"
	"github.com/xtls/xray-core/testing/servers/tcp"
	xTLS "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

// Run against binaries built from anytls/anytls-go tag v0.0.13, without adding
// a dependency on the reference implementation to the Xray module.
func TestAnyTLSUpstreamInterop(t *testing.T) {
	upstreamServer := os.Getenv("XRAY_ANYTLS_UPSTREAM_SERVER")
	upstreamClient := os.Getenv("XRAY_ANYTLS_UPSTREAM_CLIENT")
	if upstreamServer == "" || upstreamClient == "" {
		t.Skip("set XRAY_ANYTLS_UPSTREAM_SERVER and XRAY_ANYTLS_UPSTREAM_CLIENT to v0.0.13 binaries")
	}
	payload := bytes.Repeat([]byte("AnyTLS HTTPS interoperability\n"), 131072)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/payload" {
			w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
			_, _ = w.Write(payload)
			return
		}
		_, _ = io.WriteString(w, "probe")
	}))
	origin.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	origin.StartTLS()
	defer origin.Close()
	originAddr := origin.Listener.Addr().(*net.TCPAddr)
	destination := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(originAddr.Port))

	for _, disableReuse := range []bool{false, true} {
		for _, direction := range []string{"native_client", "native_server"} {
			t.Run(fmt.Sprintf("%s/disableReuse=%t", direction, disableReuse), func(t *testing.T) {
				serverPort, clientPort := tcp.PickPort(), tcp.PickPort()
				serverConfig, clientConfig := anyTLSConfigs(serverPort, clientPort, destination, xnet.Network_TCP)
				transport := &http.Transport{
					DisableKeepAlives: true,
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // isolated httptest origin
						MinVersion:         tls.VersionTLS13,
						NextProtos:         []string{"http/1.1"},
					},
				}
				t.Cleanup(transport.CloseIdleConnections)
				if direction == "native_client" {
					anyTLSStartReference(t, upstreamServer, "-l", fmt.Sprintf("127.0.0.1:%d", serverPort), "-p", "anytls-password")
					anyTLSWaitReference(t, fmt.Sprintf("127.0.0.1:%d", serverPort))
					conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), &tls.Config{InsecureSkipVerify: true})
					if err != nil {
						t.Fatal(err)
					}
					pin := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
					_ = conn.Close()
					var sender proxyman.SenderConfig
					if err := proto.Unmarshal(clientConfig.Outbound[0].SenderSettings.Value, &sender); err != nil {
						t.Fatal(err)
					}
					sender.StreamSettings.SecuritySettings[0] = serial.ToTypedMessage(&xTLS.Config{PinnedPeerCertSha256: [][]byte{pin[:]}})
					clientConfig.Outbound[0].SenderSettings = serial.ToTypedMessage(&sender)
					var outbound anytls.ClientConfig
					if err := proto.Unmarshal(clientConfig.Outbound[0].ProxySettings.Value, &outbound); err != nil {
						t.Fatal(err)
					}
					outbound.DisableSessionReuse = disableReuse
					clientConfig.Outbound[0].ProxySettings = serial.ToTypedMessage(&outbound)
					servers, err := InitializeServerConfigs(clientConfig)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { CloseAllServers(servers) })
					transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", clientPort))
					}
				} else {
					servers, err := InitializeServerConfigs(serverConfig)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { CloseAllServers(servers) })
					args := []string{"-l", fmt.Sprintf("127.0.0.1:%d", clientPort), "-s", fmt.Sprintf("127.0.0.1:%d", serverPort), "-p", "anytls-password"}
					if disableReuse {
						args = append(args, "-dr")
					}
					anyTLSStartReference(t, upstreamClient, args...)
					anyTLSWaitReference(t, fmt.Sprintf("127.0.0.1:%d", clientPort))
					proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", clientPort))
					transport.Proxy = http.ProxyURL(proxyURL)
				}
				client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
				for i := 0; i < 8; i++ {
					path, want := "/probe", []byte("probe")
					if i%3 == 0 {
						path, want = "/payload", payload
					}
					response, err := client.Get(origin.URL + path)
					if err != nil {
						t.Fatal(err)
					}
					got, readErr := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(got, want) {
						t.Fatalf("request %d: status=%d bytes=%d/%d err=%v", i, response.StatusCode, len(got), len(want), readErr)
					}
					if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.ProtoMajor != 1 {
						t.Fatalf("expected inner TLS1.3 HTTP/1.1, got TLS=%v protocol=%s", response.TLS, response.Proto)
					}
				}
			})
		}
	}
}

func anyTLSStartReference(t *testing.T, executable string, args ...string) {
	t.Helper()
	log, err := os.Create(filepath.Join(t.TempDir(), "upstream.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, args...)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait(); _ = log.Close() })
}

func anyTLSWaitReference(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("reference listener did not start: %s", address)
}
