package scenarios

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/anytls"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"golang.org/x/sync/errgroup"
)

const (
	anyTLSHTTPSChunkSize      = 32 * 1024
	anyTLSHTTPSDefaultBytes   = 128 * 1024
	anyTLSHTTPSSustainedBytes = 9_830_400
)

type anyTLSHTTPSMode struct {
	name         string
	direct       bool
	disableReuse bool
	minIdle      *uint32
	clientPort   net.Port
}

func TestAnyTLSHTTPSHTTP11TLS13(t *testing.T) {
	size := anyTLSHTTPSDefaultBytes
	probeInterval := 250 * time.Millisecond
	transferTimeout := 30 * time.Second
	if os.Getenv("XRAY_ANYTLS_SUSTAINED") == "1" {
		size = anyTLSHTTPSSustainedBytes
		probeInterval = 5 * time.Second
		transferTimeout = 8*time.Minute + 10*time.Second
	}

	origin := httptest.NewUnstartedServer(http.HandlerFunc(anyTLSHTTPSHandler))
	origin.EnableHTTP2 = false
	origin.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	origin.StartTLS()
	defer origin.Close()

	destination := net.DestinationFromAddr(origin.Listener.Addr())
	modes := []anyTLSHTTPSMode{
		{name: "direct", direct: true},
		{name: "default-reuse"},
		{name: "min-idle-zero", minIdle: uint32Pointer(0)},
		{name: "no-reuse", disableReuse: true},
	}

	var configs []*core.Config
	for i := range modes {
		if modes[i].direct {
			continue
		}
		serverPort, clientPort := tcp.PickPort(), tcp.PickPort()
		modes[i].clientPort = clientPort
		serverConfig, clientConfig := anyTLSConfigs(serverPort, clientPort, destination, net.Network_TCP)
		instance, err := clientConfig.Outbound[0].ProxySettings.GetInstance()
		if err != nil {
			t.Fatalf("decode AnyTLS client config for %s: %v", modes[i].name, err)
		}
		anyTLSConfig := instance.(*anytls.ClientConfig)
		anyTLSConfig.DisableSessionReuse = modes[i].disableReuse
		anyTLSConfig.MinIdleSession = modes[i].minIdle
		clientConfig.Outbound[0].ProxySettings = serial.ToTypedMessage(anyTLSConfig)
		configs = append(configs, serverConfig, clientConfig)
	}

	servers, err := InitializeServerConfigs(configs...)
	if err != nil {
		t.Fatalf("initialize AnyTLS HTTPS scenarios: %v", err)
	}
	defer CloseAllServers(servers)

	type modeResult struct {
		name   string
		probes int64
	}
	results := make(chan modeResult, len(modes))
	var group errgroup.Group
	for _, mode := range modes {
		mode := mode
		group.Go(func() error {
			probes, err := runAnyTLSHTTPSMode(origin, mode, size, probeInterval, transferTimeout)
			if err != nil {
				return fmt.Errorf("%s: %w", mode.name, err)
			}
			results <- modeResult{name: mode.name, probes: probes}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}
	close(results)
	for result := range results {
		t.Logf("%s completed %d concurrent short HTTPS probes during %d-byte slow read", result.name, result.probes, size)
	}
}

func runAnyTLSHTTPSMode(origin *httptest.Server, mode anyTLSHTTPSMode, size int, probeInterval, transferTimeout time.Duration) (int64, error) {
	transport := origin.Client().Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	if !mode.direct {
		dialer := &stdnet.Dialer{Timeout: 5 * time.Second}
		clientAddress := stdnet.JoinHostPort("127.0.0.1", mode.clientPort.String())
		transport.DialContext = func(ctx context.Context, network, _ string) (stdnet.Conn, error) {
			return dialer.DialContext(ctx, network, clientAddress)
		}
	}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()

	requestContext, cancelRequest := context.WithTimeout(context.Background(), transferTimeout)
	defer cancelRequest()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, origin.URL+"/slow?bytes="+strconv.Itoa(size), nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("start slow HTTPS request: %w", err)
	}
	defer response.Body.Close()
	if err := checkAnyTLSHTTPSResponse(response); err != nil {
		return 0, err
	}
	if response.StatusCode != http.StatusOK || response.ContentLength != int64(size) {
		return 0, fmt.Errorf("slow HTTPS response status/content length = %d/%d, want %d/%d", response.StatusCode, response.ContentLength, http.StatusOK, size)
	}
	wantHash := hex.EncodeToString(anyTLSHTTPSBodyHash(size))
	if gotHash := response.Header.Get("X-Body-SHA256"); gotHash != wantHash {
		return 0, fmt.Errorf("origin checksum header = %q, want %q", gotHash, wantHash)
	}

	probeContext, cancelProbes := context.WithCancel(context.Background())
	probeStop := make(chan struct{})
	var probeStopOnce sync.Once
	stopProbeSchedule := func() {
		probeStopOnce.Do(func() { close(probeStop) })
	}
	probeDone := make(chan struct{})
	probeErrors := make(chan error, 1)
	var probeCount atomic.Int64
	go func() {
		defer close(probeDone)
		probe := func() error {
			ctx, cancel := context.WithTimeout(probeContext, 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL+"/probe", nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("short HTTPS probe: %w", err)
			}
			defer resp.Body.Close()
			if err := checkAnyTLSHTTPSResponse(resp); err != nil {
				return err
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("read short HTTPS probe: %w", err)
			}
			if resp.StatusCode != http.StatusOK || string(body) != "ok" {
				return fmt.Errorf("short HTTPS probe response = %d/%q, want %d/%q", resp.StatusCode, body, http.StatusOK, "ok")
			}
			probeCount.Add(1)
			return nil
		}
		if err := probe(); err != nil {
			probeErrors <- err
			return
		}
		ticker := time.NewTicker(probeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-probeContext.Done():
				return
			case <-probeStop:
				return
			case <-ticker.C:
				select {
				case <-probeStop:
					return
				default:
				}
				if err := probe(); err != nil {
					probeErrors <- err
					return
				}
			}
		}
	}()

	hash := sha256.New()
	remaining := size
	buffer := make([]byte, anyTLSHTTPSChunkSize)
	for remaining > 0 {
		chunkSize := min(remaining, len(buffer))
		timer := time.NewTimer(time.Duration(chunkSize) * time.Second / anyTLSHTTPSChunkSize)
		select {
		case <-requestContext.Done():
			timer.Stop()
			stopProbeSchedule()
			cancelProbes()
			<-probeDone
			return probeCount.Load(), fmt.Errorf("slow HTTPS request exceeded %s: %w", transferTimeout, requestContext.Err())
		case <-timer.C:
		}
		select {
		case err := <-probeErrors:
			stopProbeSchedule()
			cancelProbes()
			<-probeDone
			return probeCount.Load(), err
		default:
		}
		n, err := io.ReadFull(response.Body, buffer[:chunkSize])
		if err != nil {
			stopProbeSchedule()
			cancelProbes()
			<-probeDone
			return probeCount.Load(), fmt.Errorf("read slow HTTPS body at %d/%d bytes: %w", size-remaining, size, err)
		}
		_, _ = hash.Write(buffer[:n])
		remaining -= n
	}
	if extra, err := response.Body.Read(buffer[:1]); extra != 0 || err != io.EOF {
		stopProbeSchedule()
		cancelProbes()
		<-probeDone
		return probeCount.Load(), fmt.Errorf("slow HTTPS body did not end after %d bytes: read %d bytes, err=%v", size, extra, err)
	}
	stopProbeSchedule()
	<-probeDone
	cancelProbes()
	select {
	case err := <-probeErrors:
		return probeCount.Load(), err
	default:
	}
	if gotHash := hex.EncodeToString(hash.Sum(nil)); gotHash != wantHash {
		return probeCount.Load(), fmt.Errorf("slow HTTPS body checksum = %s, want %s", gotHash, wantHash)
	}
	if probeCount.Load() == 0 {
		return 0, fmt.Errorf("no short HTTPS probes completed during slow body read")
	}
	return probeCount.Load(), nil
}

func checkAnyTLSHTTPSResponse(response *http.Response) error {
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		version := uint16(0)
		if response.TLS != nil {
			version = response.TLS.Version
		}
		return fmt.Errorf("negotiated HTTPS TLS version = %#04x, want TLS 1.3", version)
	}
	if response.Proto != "HTTP/1.1" || response.Header.Get("X-Origin-Protocol") != "HTTP/1.1" {
		return fmt.Errorf("HTTPS protocol = client %q, origin %q; want HTTP/1.1", response.Proto, response.Header.Get("X-Origin-Protocol"))
	}
	if response.Header.Get("X-Origin-TLS-Version") != strconv.Itoa(int(tls.VersionTLS13)) {
		return fmt.Errorf("origin TLS version header = %q, want TLS 1.3", response.Header.Get("X-Origin-TLS-Version"))
	}
	return nil
}

func anyTLSHTTPSHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("X-Origin-Protocol", request.Proto)
	if request.TLS != nil {
		response.Header().Set("X-Origin-TLS-Version", strconv.Itoa(int(request.TLS.Version)))
	}
	if request.URL.Path == "/probe" {
		_, _ = io.WriteString(response, "ok")
		return
	}
	if request.URL.Path != "/slow" {
		http.NotFound(response, request)
		return
	}
	size, err := strconv.Atoi(request.URL.Query().Get("bytes"))
	if err != nil || size <= 0 || size > anyTLSHTTPSSustainedBytes {
		http.Error(response, "invalid byte count", http.StatusBadRequest)
		return
	}
	response.Header().Set("Content-Length", strconv.Itoa(size))
	response.Header().Set("X-Body-SHA256", hex.EncodeToString(anyTLSHTTPSBodyHash(size)))
	buffer := make([]byte, anyTLSHTTPSChunkSize)
	for offset := 0; offset < size; {
		chunkSize := min(size-offset, len(buffer))
		fillAnyTLSHTTPSBody(buffer[:chunkSize], offset)
		written, err := response.Write(buffer[:chunkSize])
		if err != nil || written != chunkSize {
			return
		}
		offset += written
	}
}

func anyTLSHTTPSBodyHash(size int) []byte {
	hash := sha256.New()
	buffer := make([]byte, anyTLSHTTPSChunkSize)
	for offset := 0; offset < size; {
		chunkSize := min(size-offset, len(buffer))
		fillAnyTLSHTTPSBody(buffer[:chunkSize], offset)
		_, _ = hash.Write(buffer[:chunkSize])
		offset += chunkSize
	}
	return hash.Sum(nil)
}

func fillAnyTLSHTTPSBody(buffer []byte, offset int) {
	for i := range buffer {
		buffer[i] = byte((offset+i)*31 + 17)
	}
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}
