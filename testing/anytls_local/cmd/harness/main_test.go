package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPatternRoundTrip(t *testing.T) {
	const size = int64(2*(64<<10) + 137)
	var payload bytes.Buffer
	if err := writePattern(&payload, size); err != nil {
		t.Fatal(err)
	}
	if int64(payload.Len()) != size {
		t.Fatalf("payload length = %d, want %d", payload.Len(), size)
	}
	if err := readAndValidatePattern(&payload, size); err != nil {
		t.Fatal(err)
	}
}

func TestPayloadServerTCPAndUDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := startPayloadServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for _, direction := range []transferDirection{directionDownload, directionUpload} {
		if err := transferOnce(ctx, server.TCPAddr(), "", direction, 128<<10); err != nil {
			t.Fatalf("%s transfer: %v", direction, err)
		}
	}
	if err := echoOnce(ctx, server.TCPAddr(), "", 32<<10); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if err := runFixedLoad(ctx, server.TCPAddr(), "", directionDownload, 4, 32<<10); err != nil {
		t.Fatalf("fixed concurrent load: %v", err)
	}
	timed, err := runTimedLoad(ctx, server.TCPAddr(), "", directionUpload, 2, 20*time.Millisecond, 32<<10)
	if err != nil {
		t.Fatalf("timed load: %v", err)
	}
	if timed.Bytes == 0 || timed.Transactions == 0 || timed.MiBPerSecond <= 0 {
		t.Fatalf("invalid timed result: %+v", timed)
	}
	if err := runChurn(ctx, server.TCPAddr(), "", 4, 20, 1024); err != nil {
		t.Fatalf("churn: %v", err)
	}
	udpTarget := net.JoinHostPort("127.0.0.1", strconv.Itoa(server.UDPPort()))
	if err := runUDPSmoke(ctx, udpTarget, 3); err != nil {
		t.Fatalf("UDP smoke: %v", err)
	}
}

func TestSOCKS5Connect(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(server, greeting); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(greeting, []byte{5, 1, 0}) {
			done <- io.ErrUnexpectedEOF
			return
		}
		if _, err := server.Write([]byte{5, 0}); err != nil {
			done <- err
			return
		}
		request := make([]byte, 10)
		if _, err := io.ReadFull(server, request); err != nil {
			done <- err
			return
		}
		if request[0] != 5 || request[1] != 1 || request[3] != 1 || !bytes.Equal(request[4:8], []byte{127, 0, 0, 1}) || binary.BigEndian.Uint16(request[8:]) != 8080 {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err := server.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		done <- err
	}()
	if err := socks5Connect(client, "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReadRuntimeStats(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/vars", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"memstats":{"HeapAlloc":11,"HeapInuse":12,"HeapSys":13,"Sys":14,"NumGC":15}}`)
	})
	mux.HandleFunc("/debug/pprof/goroutine", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "goroutine profile: total 16\n")
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	stats, err := readRuntimeStats(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if stats.HeapAlloc != 11 || stats.HeapInuse != 12 || stats.HeapSys != 13 || stats.Sys != 14 || stats.NumGC != 15 || stats.Goroutines != 16 {
		t.Fatalf("unexpected runtime stats: %+v", stats)
	}
}

func TestParseOptionsAndSummary(t *testing.T) {
	opts, err := parseOptions([]string{"--duration", "2s", "--concurrency", "2,4", "--churn", "10"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.duration != 2*time.Second || len(opts.concurrency) != 2 || opts.concurrency[0] != 2 || opts.concurrency[1] != 4 || opts.churn != 10 {
		t.Fatalf("unexpected options: %+v", opts)
	}

	dir := t.TempDir()
	reporter, err := newReporter(dir)
	if err != nil {
		t.Fatal(err)
	}
	reporter.addThroughput(throughputRecord{Mode: "direct", Direction: "download", Concurrency: 1, Bytes: 100, Transactions: 1, Elapsed: time.Second, MiBPerSecond: 100})
	reporter.addThroughput(throughputRecord{Mode: "default_reuse", Direction: "download", Concurrency: 1, Bytes: 80, Transactions: 1, Elapsed: time.Second, MiBPerSecond: 80})
	reporter.addCheck(checkRecord{Mode: "default_reuse", Name: "uot_smoke", Detail: "3/3 datagrams"})
	reporter.addMemory(memoryRecord{Mode: "default_reuse", Phase: "default_reuse/startup_idle", Role: "client", RSSKiB: 100, HeapAlloc: 1 << 20, Goroutines: 5})
	reporter.addMemory(memoryRecord{Mode: "default_reuse", Phase: "default_reuse/recovery", Role: "client", RSSKiB: 110, HeapAlloc: 2 << 20, Goroutines: 6})
	if err := reporter.writeSummary(); err != nil {
		t.Fatal(err)
	}
	reporter.close()
	content, err := os.ReadFile(filepath.Join(dir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, expected := range []string{"80.00%", "3/3 datagrams", "+10"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("summary missing %q:\n%s", expected, text)
		}
	}
}
