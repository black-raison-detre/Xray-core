package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	defaultTransferSize  = int64(8 << 20)
	defaultIntegritySize = int64(1 << 20)
	churnPayloadSize     = int64(4 << 10)
)

var cipherMethods = []string{
	"none", "table", "rc4", "rc4-md5-6", "rc4-md5",
	"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
	"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb",
	"camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
	"cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
	"salsa20", "chacha20", "chacha20-ietf",
}

var protocolNames = []string{
	"origin", "auth_sha1", "auth_sha1_v2", "auth_sha1_v4",
	"auth_aes128_md5", "auth_aes128_sha1",
	"auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f",
	"auth_akarin_rand", "auth_akarin_spec_a",
}

var obfsNames = []string{"plain", "http_simple", "http_post", "tls1.2_ticket_auth"}

var udpProtocolNames = []string{
	"auth_aes128_md5", "auth_aes128_sha1",
	"auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f",
	"auth_akarin_rand", "auth_akarin_spec_a",
}

type options struct {
	xrayBin         string
	ssrSource       string
	ssrServerBin    string
	resultsDir      string
	duration        time.Duration
	repetitions     int
	concurrency     []int
	churn           int
	recovery        time.Duration
	sampleEvery     time.Duration
	startupIdle     time.Duration
	warmup          time.Duration
	startupWait     time.Duration
	udpPackets      int
	transferSize    int64
	integritySize   int64
	quick           bool
	concurrencyText string
}

type ssrMode struct {
	name     string
	method   string
	protocol string
	obfs     string
	network  string
}

type portSet struct {
	server  int
	socks   int
	metrics int
}

type processPair struct {
	server     *managedProcess
	xray       *managedProcess
	socksAddr  string
	metricsURL string
}

type harness struct {
	opts             options
	root             string
	resultsDir       string
	xrayBin          string
	ssrServerBin     string
	ssrLocalBin      string
	serverSource     string
	password         string
	xrayBuildCommand string
	ssrBuildCommand  string
	payload          *payloadServer
	reporter         *reporter
	phase            phaseValue
	temporaryBuild   string
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "ssr local harness:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	h := &harness{opts: opts}
	if err := h.run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "ssr local harness:", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("ssr-local", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.xrayBin, "xray-bin", "", "prebuilt Xray executable (default: build current checkout)")
	fs.StringVar(&opts.ssrSource, "ssr-source", "", "shadowsocksr-libev source checkout")
	fs.StringVar(&opts.ssrServerBin, "ssr-server-bin", "", "prebuilt ss-server executable (skips source preflight)")
	fs.StringVar(&opts.resultsDir, "results", "", "result directory (default: testing/ssr_local/results/<UTC timestamp>)")
	fs.DurationVar(&opts.duration, "duration", 10*time.Second, "duration of each timed throughput case")
	fs.IntVar(&opts.repetitions, "repetitions", 3, "timed repetitions per direction and concurrency")
	fs.StringVar(&opts.concurrencyText, "concurrency", "1,8,32", "comma-separated TCP concurrency levels")
	fs.IntVar(&opts.churn, "churn", 2000, "number of short TCP round trips per representative mode")
	fs.DurationVar(&opts.recovery, "recovery", 65*time.Second, "post-load idle recovery window")
	fs.DurationVar(&opts.sampleEvery, "sample-interval", time.Second, "process memory sample interval")
	fs.DurationVar(&opts.startupIdle, "startup-idle", 5*time.Second, "startup idle baseline window")
	fs.DurationVar(&opts.warmup, "warmup", 3*time.Second, "unreported warmup per transfer direction")
	fs.DurationVar(&opts.startupWait, "startup-timeout", 15*time.Second, "per-process readiness timeout")
	fs.IntVar(&opts.udpPackets, "udp-packets", 100, "SOCKS UDP echo datagrams per representative mode")
	fs.Int64Var(&opts.transferSize, "transfer-size", defaultTransferSize, "bytes per timed TCP transaction")
	fs.Int64Var(&opts.integritySize, "integrity-size", defaultIntegritySize, "bytes per fixed integrity stream")
	fs.BoolVar(&opts.quick, "quick", false, "run one shortened representative case")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if opts.ssrSource != "" && opts.ssrServerBin != "" {
		return opts, errors.New("--ssr-source and --ssr-server-bin are mutually exclusive")
	}
	if opts.ssrSource == "" && opts.ssrServerBin == "" {
		return opts, errors.New("one of --ssr-source or --ssr-server-bin is required")
	}
	for _, item := range strings.Split(opts.concurrencyText, ",") {
		value, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || value <= 0 {
			return opts, fmt.Errorf("invalid concurrency value %q", item)
		}
		opts.concurrency = append(opts.concurrency, value)
	}
	if opts.duration <= 0 || opts.repetitions <= 0 || len(opts.concurrency) == 0 || opts.sampleEvery <= 0 || opts.startupWait <= 0 {
		return opts, errors.New("duration, repetitions, concurrency, sample interval, and startup timeout must be positive")
	}
	if opts.churn < 0 || opts.recovery < 0 || opts.startupIdle < 0 || opts.warmup < 0 || opts.udpPackets < 0 {
		return opts, errors.New("churn, recovery, idle, warmup, and UDP packet values cannot be negative")
	}
	if opts.transferSize <= 0 || opts.integritySize <= 0 {
		return opts, errors.New("transfer and integrity sizes must be positive")
	}
	if opts.quick {
		opts.duration = 2 * time.Second
		opts.repetitions = 1
		opts.concurrency = []int{1}
		opts.churn = 32
		opts.recovery = time.Second
		opts.startupIdle = time.Second
		opts.warmup = time.Second
		opts.udpPackets = 10
		opts.transferSize = 1 << 20
		opts.integritySize = 128 << 10
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
		h.resultsDir = filepath.Join(root, "testing", "ssr_local", "results", time.Now().UTC().Format("20060102T150405Z"))
	} else if h.resultsDir, err = filepath.Abs(h.opts.resultsDir); err != nil {
		return err
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
		if h.temporaryBuild != "" {
			_ = os.RemoveAll(h.temporaryBuild)
		}
	}()

	h.reporter.logf("results: %s", h.resultsDir)
	if err := h.preparePassword(); err != nil {
		return err
	}
	if err := h.resolveBinaries(ctx); err != nil {
		return err
	}
	h.payload, err = startPayloadServer(ctx)
	if err != nil {
		return err
	}
	if err := h.writeManifest(); err != nil {
		return err
	}
	if h.ssrLocalBin != "" {
		if err := h.runCPreflight(ctx); err != nil {
			return err
		}
	} else {
		h.reporter.logf("C checkout preflight skipped: --ssr-server-bin override selected")
	}
	if err := h.runCompatibilitySweep(ctx); err != nil {
		return err
	}
	if err := h.runDirectBaseline(ctx); err != nil {
		return err
	}
	for _, mode := range h.performanceModes() {
		if err := h.runPerformanceMode(ctx, mode); err != nil {
			return err
		}
	}
	h.phase.Store("complete")
	h.reporter.logf("completed successfully")
	return nil
}

func (h *harness) preparePassword() error {
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	h.password = hex.EncodeToString(secret)
	return nil
}

func (h *harness) resolveBinaries(ctx context.Context) error {
	binDir := filepath.Join(h.resultsDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	if h.opts.xrayBin != "" {
		path, err := executablePath(h.opts.xrayBin)
		if err != nil {
			return fmt.Errorf("Xray binary: %w", err)
		}
		h.xrayBin = path
	} else {
		h.xrayBin = filepath.Join(binDir, "xray")
		if runtime.GOOS == "windows" {
			h.xrayBin += ".exe"
		}
		h.xrayBuildCommand = fmt.Sprintf("CGO_ENABLED=0 go build -o %q -trimpath -buildvcs=false -ldflags=%q ./main", h.xrayBin, "-s -w -buildid=")
		h.reporter.logf("building Xray: %s", h.xrayBin)
		cmd := exec.CommandContext(ctx, "go", "build", "-o", h.xrayBin, "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "./main")
		cmd.Dir = h.root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if err := runCommandToLog(cmd, filepath.Join(h.resultsDir, "xray-build.log")); err != nil {
			return fmt.Errorf("build Xray: %w", err)
		}
	}
	if h.opts.ssrServerBin != "" {
		path, err := executablePath(h.opts.ssrServerBin)
		if err != nil {
			return fmt.Errorf("ss-server binary: %w", err)
		}
		h.ssrServerBin = path
		return nil
	}
	return h.buildSSRServer(ctx, binDir)
}

func (h *harness) buildSSRServer(ctx context.Context, binDir string) error {
	source, err := filepath.Abs(h.opts.ssrSource)
	if err != nil {
		return err
	}
	if info, err := os.Stat(filepath.Join(source, "CMakeLists.txt")); err != nil || info.IsDir() {
		return fmt.Errorf("invalid shadowsocksr-libev source checkout: %s", source)
	}
	h.serverSource = source
	h.temporaryBuild, err = os.MkdirTemp("", "xray-ssr-libev-build-")
	if err != nil {
		return err
	}
	configureArgs := []string{"-S", source, "-B", h.temporaryBuild, "-DENABLE_SYSTEM_SHARED_LIB=ON"}
	if opensslRoot := detectOpenSSLRoot(ctx); opensslRoot != "" {
		configureArgs = append(configureArgs, "-DOPENSSL_ROOT_DIR="+opensslRoot)
	}
	h.ssrBuildCommand = "cmake " + strings.Join(configureArgs, " ") + " && cmake --build " + h.temporaryBuild + " --target ss-local ss-server"
	h.reporter.logf("building shadowsocksr-libev from %s", source)
	configure := exec.CommandContext(ctx, "cmake", configureArgs...)
	configure.Dir = source
	if err := runCommandToLog(configure, filepath.Join(h.resultsDir, "ssr-cmake-configure.log")); err != nil {
		return fmt.Errorf("configure shadowsocksr-libev: %w", err)
	}
	build := exec.CommandContext(ctx, "cmake", "--build", h.temporaryBuild, "--target", "ss-local", "ss-server")
	build.Dir = source
	if err := runCommandToLog(build, filepath.Join(h.resultsDir, "ssr-cmake-build.log")); err != nil {
		return fmt.Errorf("build shadowsocksr-libev: %w", err)
	}
	h.ssrServerBin = filepath.Join(binDir, "ss-server")
	h.ssrLocalBin = filepath.Join(binDir, "ss-local")
	if err := copyExecutable(filepath.Join(h.temporaryBuild, "src", "ss-server"), h.ssrServerBin); err != nil {
		return err
	}
	return copyExecutable(filepath.Join(h.temporaryBuild, "src", "ss-local"), h.ssrLocalBin)
}

func detectOpenSSLRoot(ctx context.Context) string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	for _, formula := range []string{"openssl@3", "openssl"} {
		cmd := exec.CommandContext(ctx, "brew", "--prefix", formula)
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return ""
}

func (h *harness) runCPreflight(ctx context.Context) error {
	h.reporter.logf("running shadowsocksr-libev quick server preflight")
	var failures []error
	for attempt := 1; attempt <= 3; attempt++ {
		logPath := filepath.Join(h.resultsDir, fmt.Sprintf("ssr-c-preflight-attempt-%d.log", attempt))
		cmd := exec.CommandContext(ctx, "python3", filepath.Join(h.serverSource, "tests", "ssr_server_loopback.py"), "--binary-dir", filepath.Dir(h.ssrServerBin), "--quick")
		cmd.Dir = h.serverSource
		if err := runCommandToLog(cmd, logPath); err == nil {
			h.reporter.logf("shadowsocksr-libev preflight passed on attempt %d", attempt)
			return nil
		} else {
			failures = append(failures, fmt.Errorf("attempt %d: %w", attempt, err))
			h.reporter.logf("shadowsocksr-libev preflight attempt %d failed; retrying", attempt)
		}
		if err := sleepContext(ctx, 250*time.Millisecond); err != nil {
			return err
		}
	}
	return fmt.Errorf("C server preflight failed after 3 attempts: %w", errors.Join(failures...))
}

func (h *harness) compatibilityModes() []ssrMode {
	if h.opts.quick {
		return []ssrMode{{name: "quick_aes256_origin_plain", method: "aes-256-cfb", protocol: "origin", obfs: "plain", network: "tcp"}}
	}
	modes := make([]ssrMode, 0, len(cipherMethods)+len(protocolNames)+len(obfsNames)+1+len(udpProtocolNames)+1)
	for _, method := range cipherMethods {
		modes = append(modes, ssrMode{name: "cipher_" + safeName(method), method: method, protocol: "origin", obfs: "plain", network: "tcp"})
	}
	for _, protocol := range protocolNames {
		modes = append(modes, ssrMode{name: "protocol_" + safeName(protocol), method: "aes-256-cfb", protocol: protocol, obfs: "plain", network: "tcp"})
	}
	for _, obfs := range obfsNames {
		modes = append(modes, ssrMode{name: "obfs_" + safeName(obfs), method: "aes-256-cfb", protocol: "origin", obfs: obfs, network: "tcp"})
	}
	modes = append(modes, ssrMode{name: "combined_full", method: "aes-256-cfb", protocol: "auth_aes128_sha1", obfs: "tls1.2_ticket_auth", network: "tcp"})
	modes = append(modes, ssrMode{name: "udp_origin", method: "aes-256-cfb", protocol: "origin", obfs: "plain", network: "udp"})
	for _, protocol := range udpProtocolNames {
		modes = append(modes, ssrMode{name: "udp_protocol_" + safeName(protocol), method: "aes-256-cfb", protocol: protocol, obfs: "plain", network: "udp"})
	}
	return modes
}

func (h *harness) performanceModes() []ssrMode {
	if h.opts.quick {
		return []ssrMode{{name: "aes256_origin_plain", method: "aes-256-cfb", protocol: "origin", obfs: "plain"}}
	}
	return []ssrMode{
		{name: "aes256_origin_plain", method: "aes-256-cfb", protocol: "origin", obfs: "plain"},
		{name: "chacha20ietf_origin_plain", method: "chacha20-ietf", protocol: "origin", obfs: "plain"},
		{name: "aes256_auth_chain_a_plain", method: "aes-256-cfb", protocol: "auth_chain_a", obfs: "plain"},
		{name: "aes256_auth_aes128_sha1_tls12", method: "aes-256-cfb", protocol: "auth_aes128_sha1", obfs: "tls1.2_ticket_auth"},
	}
}

func (h *harness) runCompatibilitySweep(ctx context.Context) error {
	modes := h.compatibilityModes()
	h.reporter.logf("Xray-to-C compatibility sweep: %d cases", len(modes))
	var failures []error
	for _, mode := range modes {
		if err := h.runCompatibilityMode(ctx, mode); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("compatibility sweep failed: %w", errors.Join(failures...))
	}
	return nil
}

func (h *harness) runCompatibilityMode(ctx context.Context, mode ssrMode) (runErr error) {
	dir := filepath.Join(h.resultsDir, "compatibility", mode.name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	pair, err := h.startPair(ctx, mode, dir)
	if err != nil {
		h.reporter.addCompatibility(compatibilityRecord{Mode: mode.name, Method: mode.method, Protocol: mode.protocol, Obfs: mode.obfs, Network: mode.network, Detail: err.Error()})
		return fmt.Errorf("%s startup: %w", mode.name, err)
	}
	defer func() {
		if err := pair.stop(); runErr == nil && err != nil {
			runErr = err
		}
	}()
	if mode.network == "udp" {
		err = runSOCKSUDPSmoke(ctx, pair.socksAddr, net.JoinHostPort("127.0.0.1", strconv.Itoa(h.payload.UDPPort())), 1)
	} else {
		err = echoOnce(ctx, h.payload.TCPAddr(), pair.socksAddr, 32<<10)
	}
	record := compatibilityRecord{Mode: mode.name, Method: mode.method, Protocol: mode.protocol, Obfs: mode.obfs, Network: mode.network, Passed: err == nil, Detail: "integrity passed"}
	if err != nil {
		record.Detail = err.Error()
	}
	h.reporter.addCompatibility(record)
	if err != nil {
		return fmt.Errorf("%s %s: %w", mode.name, mode.network, err)
	}
	return nil
}

func (h *harness) runDirectBaseline(ctx context.Context) error {
	h.reporter.logf("direct loopback throughput baseline")
	if h.opts.warmup > 0 {
		for _, direction := range []transferDirection{directionDownload, directionUpload} {
			if _, err := runTimedLoad(ctx, h.payload.TCPAddr(), "", direction, 8, h.opts.warmup, h.opts.transferSize); err != nil {
				return fmt.Errorf("direct %s warmup: %w", direction, err)
			}
		}
	}
	for repetition := 1; repetition <= h.opts.repetitions; repetition++ {
		for _, direction := range []transferDirection{directionDownload, directionUpload} {
			for _, concurrency := range h.opts.concurrency {
				result, err := runTimedLoad(ctx, h.payload.TCPAddr(), "", direction, concurrency, h.opts.duration, h.opts.transferSize)
				if err != nil {
					return fmt.Errorf("direct %s c%d repetition %d: %w", direction, concurrency, repetition, err)
				}
				result.Mode = "direct"
				result.Repetition = repetition
				h.reporter.addThroughput(result)
			}
		}
	}
	return nil
}

func (h *harness) runPerformanceMode(ctx context.Context, mode ssrMode) (runErr error) {
	h.reporter.logf("performance mode %s", mode.name)
	dir := filepath.Join(h.resultsDir, "modes", mode.name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	pair, err := h.startPair(ctx, mode, dir)
	if err != nil {
		return err
	}
	defer func() {
		if err := pair.stop(); runErr == nil && err != nil {
			runErr = err
		}
	}()
	modeCtx, cancel := context.WithCancel(ctx)
	monitorDone := make(chan error, 1)
	go func() {
		err := h.reporter.monitor(modeCtx, mode.name, &h.phase, h.opts.sampleEvery,
			monitoredProcess{role: "xray-client", process: pair.xray, metricsURL: pair.metricsURL},
			monitoredProcess{role: "ss-server", process: pair.server})
		if err != nil && !errors.Is(err, context.Canceled) {
			cancel()
		}
		monitorDone <- err
	}()
	defer func() {
		cancel()
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

	h.phase.Store(mode.name + "/startup_idle")
	if err := sleepContext(ctx, h.opts.startupIdle); err != nil {
		return err
	}
	for _, direction := range []transferDirection{directionDownload, directionUpload} {
		for _, concurrency := range []int{1, 32} {
			h.phase.Store(fmt.Sprintf("%s/integrity/%s/c%d", mode.name, direction, concurrency))
			if err := runFixedLoad(ctx, h.payload.TCPAddr(), pair.socksAddr, direction, concurrency, h.opts.integritySize); err != nil {
				return fmt.Errorf("mode %s integrity %s c%d: %w", mode.name, direction, concurrency, err)
			}
		}
	}
	h.phase.Store(mode.name + "/udp_smoke")
	if err := runSOCKSUDPSmoke(ctx, pair.socksAddr, net.JoinHostPort("127.0.0.1", strconv.Itoa(h.payload.UDPPort())), h.opts.udpPackets); err != nil {
		return fmt.Errorf("mode %s UDP smoke: %w", mode.name, err)
	}
	if h.opts.warmup > 0 {
		for _, direction := range []transferDirection{directionDownload, directionUpload} {
			h.phase.Store(mode.name + "/warmup/" + string(direction))
			if _, err := runTimedLoad(ctx, h.payload.TCPAddr(), pair.socksAddr, direction, 8, h.opts.warmup, h.opts.transferSize); err != nil {
				return fmt.Errorf("mode %s %s warmup: %w", mode.name, direction, err)
			}
		}
	}
	for repetition := 1; repetition <= h.opts.repetitions; repetition++ {
		for _, direction := range []transferDirection{directionDownload, directionUpload} {
			for _, concurrency := range h.opts.concurrency {
				h.phase.Store(fmt.Sprintf("%s/throughput/%s/c%d/r%d", mode.name, direction, concurrency, repetition))
				result, err := runTimedLoad(ctx, h.payload.TCPAddr(), pair.socksAddr, direction, concurrency, h.opts.duration, h.opts.transferSize)
				if err != nil {
					return fmt.Errorf("mode %s %s c%d repetition %d: %w", mode.name, direction, concurrency, repetition, err)
				}
				result.Mode = mode.name
				result.Method = mode.method
				result.Protocol = mode.protocol
				result.Obfs = mode.obfs
				result.Repetition = repetition
				h.reporter.addThroughput(result)
			}
		}
	}
	h.phase.Store(mode.name + "/churn")
	if err := runChurn(ctx, h.payload.TCPAddr(), pair.socksAddr, 32, h.opts.churn, churnPayloadSize); err != nil {
		return fmt.Errorf("mode %s churn: %w", mode.name, err)
	}
	h.phase.Store(mode.name + "/recovery")
	return sleepContext(ctx, h.opts.recovery)
}

func (h *harness) startPair(ctx context.Context, mode ssrMode, dir string) (*processPair, error) {
	ports, err := allocatePorts()
	if err != nil {
		return nil, err
	}
	serverConfig := filepath.Join(dir, "server.json")
	xrayConfig := filepath.Join(dir, "xray.json")
	if err := h.writeConfigs(mode, ports, serverConfig, xrayConfig); err != nil {
		return nil, err
	}
	if err := validateXrayConfig(ctx, h.xrayBin, xrayConfig); err != nil {
		return nil, fmt.Errorf("Xray config: %w", err)
	}
	server, err := startProcess("ss-server", filepath.Join(dir, "ss-server.log"), h.ssrServerBin, "-c", serverConfig)
	if err != nil {
		return nil, err
	}
	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.server))
	if err := waitForTCP(ctx, server, serverAddr, h.opts.startupWait); err != nil {
		_ = server.stop()
		return nil, err
	}
	xray, err := startProcess("xray-client", filepath.Join(dir, "xray.log"), h.xrayBin, "run", "-c", xrayConfig)
	if err != nil {
		_ = server.stop()
		return nil, err
	}
	metricsURL := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.metrics))
	if err := waitForMetrics(ctx, xray, metricsURL, h.opts.startupWait); err != nil {
		_ = xray.stop()
		_ = server.stop()
		return nil, err
	}
	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.socks))
	if err := waitForTCP(ctx, xray, socksAddr, h.opts.startupWait); err != nil {
		_ = xray.stop()
		_ = server.stop()
		return nil, err
	}
	return &processPair{
		server: server, xray: xray,
		socksAddr: socksAddr, metricsURL: metricsURL,
	}, nil
}

func (p *processPair) stop() error {
	if p == nil {
		return nil
	}
	return errors.Join(p.xray.stop(), p.server.stop())
}

func (h *harness) writeConfigs(mode ssrMode, ports portSet, serverPath, xrayPath string) error {
	obfsParam := ""
	if mode.obfs == "tls1.2_ticket_auth" {
		obfsParam = "example.com"
	}
	server := map[string]any{
		"server": "127.0.0.1", "server_port": ports.server, "password": h.password,
		"method": mode.method, "protocol": mode.protocol, "protocol_param": "",
		"obfs": mode.obfs, "obfs_param": obfsParam, "mode": "tcp_and_udp", "timeout": 60,
	}
	xray := map[string]any{
		"log":     map[string]any{"loglevel": "warning"},
		"metrics": map[string]any{"listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.metrics))},
		"inbounds": []any{map[string]any{
			"tag": "socks-in", "listen": "127.0.0.1", "port": ports.socks, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		}},
		"outbounds": []any{map[string]any{
			"tag": "ssr-out", "protocol": "shadowsocksr",
			"settings": map[string]any{
				"address": "127.0.0.1", "port": ports.server, "password": h.password,
				"method": mode.method, "protocol": mode.protocol, "protocolParam": "",
				"obfs": mode.obfs, "obfsParam": obfsParam,
			},
		}},
	}
	if err := writeJSON(serverPath, server); err != nil {
		return err
	}
	return writeJSON(xrayPath, xray)
}

func allocatePorts() (portSet, error) {
	ports, err := pickFreePorts(3)
	if err != nil {
		return portSet{}, err
	}
	return portSet{server: ports[0], socks: ports[1], metrics: ports[2]}, nil
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

func (h *harness) writeManifest() error {
	xrayHash, err := fileSHA256(h.xrayBin)
	if err != nil {
		return err
	}
	serverHash, err := fileSHA256(h.ssrServerBin)
	if err != nil {
		return err
	}
	manifest := map[string]any{
		"createdAt": time.Now().UTC().Format(time.RFC3339Nano), "arguments": os.Args[1:],
		"host": map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "goVersion": runtime.Version(), "uname": commandText("", "uname", "-a")},
		"xray": map[string]any{
			"repository": h.root, "commit": commandText(h.root, "git", "rev-parse", "HEAD"), "branch": commandText(h.root, "git", "branch", "--show-current"),
			"dirtyState": commandText(h.root, "git", "status", "--short"), "binary": h.xrayBin, "sha256": xrayHash, "buildCommand": h.xrayBuildCommand,
		},
		"ssrServer": map[string]any{
			"source": h.serverSource, "commit": commandText(h.serverSource, "git", "rev-parse", "HEAD"), "branch": commandText(h.serverSource, "git", "branch", "--show-current"),
			"dirtyState": commandText(h.serverSource, "git", "status", "--short"), "binary": h.ssrServerBin, "sha256": serverHash, "buildCommand": h.ssrBuildCommand,
		},
		"workload": map[string]any{
			"quick": h.opts.quick, "duration": h.opts.duration.String(), "repetitions": h.opts.repetitions, "concurrency": h.opts.concurrency,
			"churn": h.opts.churn, "recovery": h.opts.recovery.String(), "sampleInterval": h.opts.sampleEvery.String(),
			"startupIdle": h.opts.startupIdle.String(), "warmup": h.opts.warmup.String(), "udpPackets": h.opts.udpPackets,
			"transferSize": h.opts.transferSize, "integritySize": h.opts.integritySize,
		},
		"payload": map[string]any{"tcp": h.payload.TCPAddr(), "udpPort": h.payload.UDPPort()},
	}
	return writeJSON(filepath.Join(h.resultsDir, "manifest.json"), manifest)
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

func copyExecutable(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

func runCommandToLog(cmd *exec.Cmd, logPath string) error {
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	cmd.Stdout = file
	cmd.Stderr = file
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w (see %s)", strings.Join(cmd.Args, " "), err, logPath)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func commandText(dir, name string, args ...string) string {
	if dir == "" && name == "git" {
		return ""
	}
	command := exec.Command(name, args...)
	if dir != "" {
		command.Dir = dir
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output))
}

func safeName(value string) string {
	return strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(value)
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
