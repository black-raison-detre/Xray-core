package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultTransferSize = int64(8 << 20)
	integritySize       = int64(1 << 20)
	churnPayloadSize    = int64(4 << 10)
)

type options struct {
	xrayBin       string
	serverBin     string
	clientBin     string
	resultsDir    string
	duration      time.Duration
	concurrency   []int
	churn         int
	recovery      time.Duration
	sampleEvery   time.Duration
	startupIdle   time.Duration
	warmup        time.Duration
	startupWait   time.Duration
	udpPackets    int
	transferSize  int64
	integritySize int64
}

type sessionMode struct {
	name                string
	minIdleSession      *uint32
	disableSessionReuse bool
}

type harness struct {
	opts         options
	root         string
	resultsDir   string
	serverBin    string
	clientBin    string
	password     string
	certPath     string
	keyPath      string
	certPin      string
	buildCommand string
	payload      *payloadServer
	reporter     *reporter
	phase        phaseValue
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "anytls harness:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	h := &harness{opts: opts}
	if err := h.run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "anytls harness:", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	var opts options
	var concurrencyText string
	fs := flag.NewFlagSet("anytls-local", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.xrayBin, "xray-bin", "", "common prebuilt Xray executable for both roles")
	fs.StringVar(&opts.serverBin, "server-bin", "", "server-role Xray executable (overrides --xray-bin)")
	fs.StringVar(&opts.clientBin, "client-bin", "", "client-role Xray executable (overrides --xray-bin)")
	fs.StringVar(&opts.resultsDir, "results", "", "result directory (default: testing/anytls_local/results/<UTC timestamp>)")
	fs.DurationVar(&opts.duration, "duration", 10*time.Second, "duration of each timed throughput case")
	fs.StringVar(&concurrencyText, "concurrency", "1,8,32", "comma-separated TCP concurrency levels")
	fs.IntVar(&opts.churn, "churn", 2000, "number of short round trips per AnyTLS mode")
	fs.DurationVar(&opts.recovery, "recovery", 65*time.Second, "post-load idle recovery window")
	fs.DurationVar(&opts.sampleEvery, "sample-interval", time.Second, "memory sample interval")
	fs.DurationVar(&opts.startupIdle, "startup-idle", 5*time.Second, "startup idle baseline window")
	fs.DurationVar(&opts.warmup, "warmup", 3*time.Second, "unreported upload and download warmup duration")
	fs.DurationVar(&opts.startupWait, "startup-timeout", 15*time.Second, "per-process metrics readiness timeout")
	fs.IntVar(&opts.udpPackets, "udp-packets", 100, "UDP-over-TCP smoke datagrams per mode")
	fs.Int64Var(&opts.transferSize, "transfer-size", defaultTransferSize, "bytes per timed TCP transaction")
	fs.Int64Var(&opts.integritySize, "integrity-size", integritySize, "bytes per fixed integrity stream")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	for _, item := range strings.Split(concurrencyText, ",") {
		value, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || value <= 0 {
			return opts, fmt.Errorf("invalid concurrency value %q", item)
		}
		opts.concurrency = append(opts.concurrency, value)
	}
	if len(opts.concurrency) == 0 || opts.duration <= 0 || opts.sampleEvery <= 0 || opts.startupWait <= 0 {
		return opts, errors.New("concurrency, duration, sample interval, and startup timeout must be positive")
	}
	if opts.churn < 0 || opts.recovery < 0 || opts.startupIdle < 0 || opts.warmup < 0 || opts.udpPackets < 0 {
		return opts, errors.New("churn, recovery, idle, warmup, and UDP packet values cannot be negative")
	}
	if opts.transferSize <= 0 || opts.integritySize <= 0 {
		return opts, errors.New("transfer and integrity sizes must be positive")
	}
	return opts, nil
}

func (h *harness) run(ctx context.Context) (runErr error) {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	h.root = root
	if h.opts.resultsDir == "" {
		h.resultsDir = filepath.Join(root, "testing", "anytls_local", "results", time.Now().UTC().Format("20060102T150405Z"))
	} else {
		h.resultsDir, err = filepath.Abs(h.opts.resultsDir)
		if err != nil {
			return err
		}
	}
	if err := ensureEmptyDirectory(h.resultsDir); err != nil {
		return fmt.Errorf("create results directory: %w", err)
	}
	h.reporter, err = newReporter(h.resultsDir)
	if err != nil {
		return err
	}
	defer func() {
		if runErr != nil {
			h.reporter.logf("FAILED: %v", runErr)
		}
		if h.payload != nil {
			h.payload.Close()
		}
		if err := h.reporter.writeSummary(); runErr == nil && err != nil {
			runErr = err
		}
		h.reporter.close()
	}()

	h.reporter.logf("results: %s", h.resultsDir)
	if err := h.resolveBinaries(ctx); err != nil {
		return err
	}
	if err := h.prepareCredentials(); err != nil {
		return err
	}
	h.payload, err = startPayloadServer(ctx)
	if err != nil {
		return err
	}
	defer h.payload.Close()
	if err := h.writeManifest(); err != nil {
		return err
	}

	h.reporter.logf("direct loopback baseline")
	if h.opts.warmup > 0 {
		for _, direction := range []transferDirection{directionDownload, directionUpload} {
			h.phase.Store("direct/warmup/" + string(direction))
			if _, err := runTimedLoad(ctx, h.payload.TCPAddr(), "", direction, 8, h.opts.warmup, h.opts.transferSize); err != nil {
				return fmt.Errorf("direct %s warmup: %w", direction, err)
			}
		}
	}
	for _, direction := range []transferDirection{directionDownload, directionUpload} {
		for _, concurrency := range h.opts.concurrency {
			h.phase.Store(fmt.Sprintf("direct/%s/c%d", direction, concurrency))
			result, err := runTimedLoad(ctx, h.payload.TCPAddr(), "", direction, concurrency, h.opts.duration, h.opts.transferSize)
			if err != nil {
				return fmt.Errorf("direct %s c%d: %w", direction, concurrency, err)
			}
			result.Mode = "direct"
			h.reporter.addThroughput(result)
		}
	}

	zero := uint32(0)
	modes := []sessionMode{
		{name: "default_reuse"},
		{name: "zero_idle_reuse", minIdleSession: &zero},
		{name: "no_reuse", minIdleSession: &zero, disableSessionReuse: true},
	}
	for _, mode := range modes {
		if err := h.runMode(ctx, mode); err != nil {
			return err
		}
	}
	h.phase.Store("complete")
	h.reporter.logf("completed successfully")
	return nil
}

func (h *harness) runMode(ctx context.Context, mode sessionMode) (runErr error) {
	h.reporter.logf("mode %s: preparing", mode.name)
	modeDir := filepath.Join(h.resultsDir, "modes", mode.name)
	if err := os.MkdirAll(modeDir, 0o755); err != nil {
		return err
	}
	serverConfig := filepath.Join(modeDir, "server.json")
	clientConfig := filepath.Join(modeDir, "client.json")
	var ports portSet
	var server, client *xrayProcess
	var startupErr error
	for attempt := 1; attempt <= 3; attempt++ {
		ports, startupErr = allocatePorts()
		if startupErr != nil {
			return startupErr
		}
		if startupErr = h.writeConfigs(mode, serverConfig, clientConfig, ports); startupErr != nil {
			return startupErr
		}
		if startupErr = validateConfig(ctx, h.serverBin, serverConfig); startupErr != nil {
			return fmt.Errorf("mode %s server config: %w", mode.name, startupErr)
		}
		if startupErr = validateConfig(ctx, h.clientBin, clientConfig); startupErr != nil {
			return fmt.Errorf("mode %s client config: %w", mode.name, startupErr)
		}
		server, startupErr = startXray(h.serverBin, serverConfig, filepath.Join(modeDir, fmt.Sprintf("server-attempt-%d.log", attempt)))
		if startupErr == nil {
			serverMetrics := fmt.Sprintf("http://127.0.0.1:%d", ports.serverMetrics)
			startupErr = waitForMetrics(ctx, server, serverMetrics, h.opts.startupWait)
		}
		if startupErr == nil {
			client, startupErr = startXray(h.clientBin, clientConfig, filepath.Join(modeDir, fmt.Sprintf("client-attempt-%d.log", attempt)))
		}
		if startupErr == nil {
			clientMetrics := fmt.Sprintf("http://127.0.0.1:%d", ports.clientMetrics)
			startupErr = waitForMetrics(ctx, client, clientMetrics, h.opts.startupWait)
		}
		if startupErr == nil {
			break
		}
		h.reporter.logf("mode %s startup attempt %d failed: %v", mode.name, attempt, startupErr)
		if client != nil {
			_ = client.stop()
			client = nil
		}
		if server != nil {
			_ = server.stop()
			server = nil
		}
	}
	if startupErr != nil {
		return fmt.Errorf("mode %s failed to start after 3 attempts: %w", mode.name, startupErr)
	}
	defer func() {
		if err := server.stop(); runErr == nil && err != nil {
			runErr = err
		}
	}()
	defer func() {
		if err := client.stop(); runErr == nil && err != nil {
			runErr = err
		}
	}()
	serverMetrics := fmt.Sprintf("http://127.0.0.1:%d", ports.serverMetrics)
	clientMetrics := fmt.Sprintf("http://127.0.0.1:%d", ports.clientMetrics)

	modeCtx, cancelMode := context.WithCancel(ctx)
	monitorDone := make(chan error, 1)
	go func() {
		err := h.reporter.monitor(modeCtx, mode.name, &h.phase, h.opts.sampleEvery,
			monitoredProcess{role: "server", process: server, metricsURL: serverMetrics},
			monitoredProcess{role: "client", process: client, metricsURL: clientMetrics})
		if err != nil && !errors.Is(err, context.Canceled) {
			cancelMode()
		}
		monitorDone <- err
	}()
	defer func() {
		cancelMode()
		if err := <-monitorDone; err != nil && !errors.Is(err, context.Canceled) {
			telemetryErr := fmt.Errorf("mode %s telemetry: %w", mode.name, err)
			if runErr == nil || errors.Is(runErr, context.Canceled) {
				runErr = telemetryErr
			} else {
				runErr = errors.Join(runErr, telemetryErr)
			}
		}
	}()
	ctx = modeCtx

	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.clientSOCKS))
	h.phase.Store(mode.name + "/startup_idle")
	if err := sleepContext(ctx, h.opts.startupIdle); err != nil {
		return err
	}
	for _, direction := range []transferDirection{directionDownload, directionUpload} {
		for _, concurrency := range []int{1, 32} {
			h.phase.Store(fmt.Sprintf("%s/integrity/%s/c%d", mode.name, direction, concurrency))
			if err := runFixedLoad(ctx, h.payload.TCPAddr(), socksAddr, direction, concurrency, h.opts.integritySize); err != nil {
				return fmt.Errorf("mode %s integrity %s c%d: %w", mode.name, direction, concurrency, err)
			}
		}
	}
	h.reporter.addCheck(checkRecord{Mode: mode.name, Name: "tcp_integrity", Detail: "upload/download passed at concurrency 1 and 32"})
	h.phase.Store(mode.name + "/uot_smoke")
	if err := runUDPSmoke(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.clientUDP)), h.opts.udpPackets); err != nil {
		return fmt.Errorf("mode %s UoT smoke: %w", mode.name, err)
	}
	h.reporter.addCheck(checkRecord{Mode: mode.name, Name: "uot_smoke", Detail: fmt.Sprintf("%d/%d datagrams", h.opts.udpPackets, h.opts.udpPackets)})

	if h.opts.warmup > 0 {
		for _, direction := range []transferDirection{directionDownload, directionUpload} {
			h.phase.Store(fmt.Sprintf("%s/warmup/%s", mode.name, direction))
			if _, err := runTimedLoad(ctx, h.payload.TCPAddr(), socksAddr, direction, 8, h.opts.warmup, h.opts.transferSize); err != nil {
				return fmt.Errorf("mode %s warmup %s: %w", mode.name, direction, err)
			}
		}
	}
	for _, direction := range []transferDirection{directionDownload, directionUpload} {
		for _, concurrency := range h.opts.concurrency {
			h.phase.Store(fmt.Sprintf("%s/throughput/%s/c%d", mode.name, direction, concurrency))
			result, err := runTimedLoad(ctx, h.payload.TCPAddr(), socksAddr, direction, concurrency, h.opts.duration, h.opts.transferSize)
			if err != nil {
				return fmt.Errorf("mode %s %s c%d: %w", mode.name, direction, concurrency, err)
			}
			result.Mode = mode.name
			h.reporter.addThroughput(result)
		}
	}
	h.phase.Store(mode.name + "/churn")
	if err := runChurn(ctx, h.payload.TCPAddr(), socksAddr, 32, h.opts.churn, churnPayloadSize); err != nil {
		return fmt.Errorf("mode %s churn: %w", mode.name, err)
	}
	h.reporter.addCheck(checkRecord{Mode: mode.name, Name: "tcp_churn", Detail: fmt.Sprintf("%d/%d round trips", h.opts.churn, h.opts.churn)})
	h.phase.Store(mode.name + "/recovery")
	if err := sleepContext(ctx, h.opts.recovery); err != nil {
		return err
	}
	return nil
}

type portSet struct {
	serverAnyTLS  int
	serverMetrics int
	clientSOCKS   int
	clientUDP     int
	clientMetrics int
}

func allocatePorts() (portSet, error) {
	ports, err := pickFreePorts(4)
	if err != nil {
		return portSet{}, err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return portSet{}, err
	}
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()
	return portSet{serverAnyTLS: ports[0], serverMetrics: ports[1], clientSOCKS: ports[2], clientUDP: udpPort, clientMetrics: ports[3]}, nil
}

func pickFreePorts(count int) ([]int, error) {
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	ports := make([]int, 0, count)
	for len(ports) < count {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

func (h *harness) resolveBinaries(ctx context.Context) error {
	h.serverBin = h.opts.serverBin
	if h.serverBin == "" {
		h.serverBin = h.opts.xrayBin
	}
	h.clientBin = h.opts.clientBin
	if h.clientBin == "" {
		h.clientBin = h.opts.xrayBin
	}
	if h.serverBin == "" || h.clientBin == "" {
		built := filepath.Join(h.resultsDir, "bin", "xray")
		if runtime.GOOS == "windows" {
			built += ".exe"
		}
		if err := os.MkdirAll(filepath.Dir(built), 0o755); err != nil {
			return err
		}
		h.reporter.logf("building current checkout once: %s", built)
		cmd := exec.CommandContext(ctx, "go", "build", "-o", built, "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "./main")
		h.buildCommand = fmt.Sprintf("CGO_ENABLED=0 go build -o %q -trimpath -buildvcs=false -ldflags=%q ./main", built, "-s -w -buildid=")
		cmd.Dir = h.root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("build Xray: %w\n%s", err, output)
		}
		if h.serverBin == "" {
			h.serverBin = built
		}
		if h.clientBin == "" {
			h.clientBin = built
		}
	}
	var err error
	if h.serverBin, err = executablePath(h.serverBin); err != nil {
		return fmt.Errorf("server binary: %w", err)
	}
	if h.clientBin, err = executablePath(h.clientBin); err != nil {
		return fmt.Errorf("client binary: %w", err)
	}
	return nil
}

func executablePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("%s is not executable", abs)
	}
	return abs, nil
}

func (h *harness) prepareCredentials() error {
	credentialDir := filepath.Join(h.resultsDir, "credentials")
	if err := os.MkdirAll(credentialDir, 0o700); err != nil {
		return err
	}
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	h.password = hex.EncodeToString(secret)
	h.certPath = filepath.Join(credentialDir, "localhost.crt")
	h.keyPath = filepath.Join(credentialDir, "localhost.key")
	certDER, err := writeCertificate(h.certPath, h.keyPath)
	if err != nil {
		return err
	}
	pin := sha256.Sum256(certDER)
	h.certPin = hex.EncodeToString(pin[:])
	return nil
}

func writeCertificate(certPath, keyPath string) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"Xray AnyTLS Local Test"}},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return der, nil
}

func (h *harness) writeConfigs(mode sessionMode, serverPath, clientPath string, ports portSet) error {
	server := map[string]any{
		"log":     map[string]any{"loglevel": "warning"},
		"metrics": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", ports.serverMetrics)},
		"inbounds": []any{map[string]any{
			"tag": "anytls-in", "listen": "127.0.0.1", "port": ports.serverAnyTLS, "protocol": "anytls",
			"settings": map[string]any{"users": []any{map[string]any{"password": h.password, "email": "local-test"}}},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "tls",
				"tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": h.certPath, "keyFile": h.keyPath}}},
			},
		}},
		"outbounds": []any{map[string]any{
			"tag": "direct", "protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{
				map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}},
				map[string]any{"action": "block"},
			}},
		}},
	}
	anyTLSSettings := map[string]any{
		"address": "127.0.0.1", "port": ports.serverAnyTLS, "password": h.password, "email": "local-test",
	}
	if mode.minIdleSession != nil {
		anyTLSSettings["minIdleSession"] = *mode.minIdleSession
	}
	if mode.disableSessionReuse {
		anyTLSSettings["disableSessionReuse"] = true
	}
	client := map[string]any{
		"log":     map[string]any{"loglevel": "warning"},
		"metrics": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", ports.clientMetrics)},
		"inbounds": []any{
			map[string]any{
				"tag": "tcp-in", "listen": "127.0.0.1", "port": ports.clientSOCKS, "protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": false},
			},
			map[string]any{
				"tag": "udp-in", "listen": "127.0.0.1", "port": ports.clientUDP, "protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1", "port": h.payload.UDPPort(), "network": "udp"},
			},
		},
		"outbounds": []any{map[string]any{
			"tag": "anytls-out", "protocol": "anytls", "settings": anyTLSSettings,
			"streamSettings": map[string]any{
				"network": "tcp", "security": "tls",
				"tlsSettings": map[string]any{"serverName": "localhost", "pinnedPeerCertSha256": h.certPin},
			},
		}},
		"routing": map[string]any{"rules": []any{map[string]any{
			"type": "field", "inboundTag": []string{"tcp-in", "udp-in"}, "outboundTag": "anytls-out",
		}}},
	}
	if err := writeJSON(serverPath, server); err != nil {
		return err
	}
	return writeJSON(clientPath, client)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func repoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("locate repository root: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func ensureEmptyDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if err == nil {
		if len(entries) != 0 {
			return fmt.Errorf("result directory is not empty: %s", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(path, 0o755)
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
