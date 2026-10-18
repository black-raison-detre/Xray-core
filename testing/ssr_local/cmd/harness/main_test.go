package main

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseOptions(t *testing.T) {
	opts, err := parseOptions([]string{"--ssr-source", "/tmp/server", "--concurrency", "2,4", "--repetitions", "2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.concurrency) != 2 || opts.concurrency[0] != 2 || opts.concurrency[1] != 4 || opts.repetitions != 2 {
		t.Fatalf("unexpected options: %+v", opts)
	}
	if _, err := parseOptions(nil); err == nil {
		t.Fatal("missing server selection was accepted")
	}
	if _, err := parseOptions([]string{"--ssr-source", "/tmp/source", "--ssr-server-bin", "/tmp/server"}); err == nil {
		t.Fatal("conflicting server selections were accepted")
	}
}

func TestQuickOptions(t *testing.T) {
	opts, err := parseOptions([]string{"--ssr-source", "/tmp/server", "--quick", "--duration", "30s", "--repetitions", "9"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.duration != 2*time.Second || opts.repetitions != 1 || len(opts.concurrency) != 1 || opts.concurrency[0] != 1 {
		t.Fatalf("quick profile was not applied: %+v", opts)
	}
}

func TestCompatibilityMatrix(t *testing.T) {
	h := &harness{}
	modes := h.compatibilityModes()
	want := len(cipherMethods) + len(protocolNames) + len(obfsNames) + 1 + 1 + len(udpProtocolNames)
	if len(modes) != want {
		t.Fatalf("compatibility cases=%d, want %d", len(modes), want)
	}
	counts := map[string]int{}
	for _, mode := range modes {
		counts[mode.network]++
		if mode.method == "" || mode.protocol == "" || mode.obfs == "" {
			t.Fatalf("incomplete mode: %+v", mode)
		}
	}
	if counts["tcp"] != 42 || counts["udp"] != 11 {
		t.Fatalf("network counts=%v, want tcp=42 udp=11", counts)
	}

	h.opts.quick = true
	modes = h.compatibilityModes()
	if len(modes) != 1 || modes[0].method != "aes-256-cfb" || modes[0].network != "tcp" {
		t.Fatalf("unexpected quick matrix: %+v", modes)
	}
}

func TestPayloadServerAndTimedLoad(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := startPayloadServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, direction := range []transferDirection{directionDownload, directionUpload} {
		if err := runFixedLoad(ctx, server.TCPAddr(), "", direction, 2, 64<<10); err != nil {
			t.Fatalf("fixed %s: %v", direction, err)
		}
		result, err := runTimedLoad(ctx, server.TCPAddr(), "", direction, 1, 20*time.Millisecond, 16<<10)
		if err != nil {
			t.Fatalf("timed %s: %v", direction, err)
		}
		if result.Bytes == 0 || result.MiBPerSecond <= 0 {
			t.Fatalf("invalid result: %+v", result)
		}
	}
}

func TestSOCKSAddressAndUDPHeader(t *testing.T) {
	address, err := socksAddress("127.0.0.1:8388")
	if err != nil {
		t.Fatal(err)
	}
	packet := append([]byte{0, 0, 0}, address...)
	packet = append(packet, []byte("payload")...)
	offset, err := socksUDPHeaderLength(packet)
	if err != nil {
		t.Fatal(err)
	}
	if string(packet[offset:]) != "payload" {
		t.Fatalf("wrong payload offset %d", offset)
	}
	if address[0] != 1 || binary.BigEndian.Uint16(address[len(address)-2:]) != 8388 {
		t.Fatalf("unexpected encoded address %v", address)
	}
	if _, err := socksAddress(net.JoinHostPort("127.0.0.1", "70000")); err == nil {
		t.Fatal("invalid port was accepted")
	}
}

func TestReporterSummary(t *testing.T) {
	dir := t.TempDir()
	r, err := newReporter(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.addCompatibility(compatibilityRecord{Mode: "case", Method: "aes-256-cfb", Protocol: "origin", Obfs: "plain", Network: "tcp", Passed: true, Detail: "ok"})
	r.addThroughput(throughputRecord{Mode: "direct", Direction: "download", Concurrency: 1, Repetition: 1, Bytes: 1024, Transactions: 1, Elapsed: time.Second, MiBPerSecond: 10})
	r.addThroughput(throughputRecord{Mode: "case", Method: "aes-256-cfb", Protocol: "origin", Obfs: "plain", Direction: "download", Concurrency: 1, Repetition: 1, Bytes: 1024, Transactions: 1, Elapsed: time.Second, MiBPerSecond: 5})
	r.addMemory(memoryRecord{Timestamp: time.Now(), Mode: "case", Phase: "case/startup_idle", Role: "ss-server", PID: os.Getpid(), RSSKiB: 100})
	if err := r.writeSummary(); err != nil {
		t.Fatal(err)
	}
	r.close()
	data, err := os.ReadFile(filepath.Join(dir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty summary")
	}
}
