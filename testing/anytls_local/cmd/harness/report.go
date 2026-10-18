package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type phaseValue struct{ value atomic.Value }

func (p *phaseValue) Store(value string) { p.value.Store(value) }
func (p *phaseValue) Load() string {
	value := p.value.Load()
	if value == nil {
		return "initializing"
	}
	return value.(string)
}

type throughputRecord struct {
	Mode         string
	Direction    string
	Concurrency  int
	Bytes        int64
	Transactions int64
	Elapsed      time.Duration
	MiBPerSecond float64
}

type checkRecord struct {
	Mode   string
	Name   string
	Detail string
}

type memoryRecord struct {
	Timestamp  time.Time
	Mode       string
	Phase      string
	Role       string
	PID        int
	RSSKiB     int64
	VSZKiB     int64
	CPUPercent float64
	HeapAlloc  uint64
	HeapInuse  uint64
	HeapSys    uint64
	Sys        uint64
	NumGC      uint32
	Goroutines int
	Error      string
}

type reporter struct {
	dir            string
	mu             sync.Mutex
	events         *os.File
	throughputFile *os.File
	throughputCSV  *csv.Writer
	memoryFile     *os.File
	memoryCSV      *csv.Writer
	throughput     []throughputRecord
	memory         []memoryRecord
	checks         []checkRecord
	closed         bool
}

func newReporter(dir string) (*reporter, error) {
	events, err := os.OpenFile(filepath.Join(dir, "events.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	throughputFile, err := os.OpenFile(filepath.Join(dir, "throughput.csv"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = events.Close()
		return nil, err
	}
	memoryFile, err := os.OpenFile(filepath.Join(dir, "memory.csv"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = events.Close()
		_ = throughputFile.Close()
		return nil, err
	}
	r := &reporter{
		dir:            dir,
		events:         events,
		throughputFile: throughputFile,
		throughputCSV:  csv.NewWriter(throughputFile),
		memoryFile:     memoryFile,
		memoryCSV:      csv.NewWriter(memoryFile),
	}
	_ = r.throughputCSV.Write([]string{"mode", "direction", "concurrency", "bytes", "transactions", "elapsed_seconds", "mib_per_second"})
	_ = r.memoryCSV.Write([]string{"timestamp", "mode", "phase", "role", "pid", "rss_kib", "vsz_kib", "cpu_percent", "heap_alloc_bytes", "heap_inuse_bytes", "heap_sys_bytes", "sys_bytes", "num_gc", "goroutines", "error"})
	r.throughputCSV.Flush()
	r.memoryCSV.Flush()
	return r, nil
}

func (r *reporter) logf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), message)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		_, _ = io.WriteString(r.events, line)
	}
	fmt.Print(line)
}

func (r *reporter) addThroughput(record throughputRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.throughput = append(r.throughput, record)
	_ = r.throughputCSV.Write([]string{
		record.Mode, record.Direction, strconv.Itoa(record.Concurrency), strconv.FormatInt(record.Bytes, 10),
		strconv.FormatInt(record.Transactions, 10), fmt.Sprintf("%.6f", record.Elapsed.Seconds()), fmt.Sprintf("%.3f", record.MiBPerSecond),
	})
	r.throughputCSV.Flush()
	r.logfUnlocked("throughput mode=%s direction=%s concurrency=%d %.2f MiB/s", record.Mode, record.Direction, record.Concurrency, record.MiBPerSecond)
}

func (r *reporter) addCheck(record checkRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks = append(r.checks, record)
	r.logfUnlocked("check mode=%s name=%s %s", record.Mode, record.Name, record.Detail)
}

func (r *reporter) logfUnlocked(format string, args ...any) {
	line := fmt.Sprintf("%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprintf(format, args...))
	if !r.closed {
		_, _ = io.WriteString(r.events, line)
	}
	fmt.Print(line)
}

func (r *reporter) addMemory(record memoryRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.memory = append(r.memory, record)
	_ = r.memoryCSV.Write([]string{
		record.Timestamp.UTC().Format(time.RFC3339Nano), record.Mode, record.Phase, record.Role, strconv.Itoa(record.PID),
		strconv.FormatInt(record.RSSKiB, 10), strconv.FormatInt(record.VSZKiB, 10), fmt.Sprintf("%.2f", record.CPUPercent),
		strconv.FormatUint(record.HeapAlloc, 10), strconv.FormatUint(record.HeapInuse, 10), strconv.FormatUint(record.HeapSys, 10),
		strconv.FormatUint(record.Sys, 10), strconv.FormatUint(uint64(record.NumGC), 10), strconv.Itoa(record.Goroutines), record.Error,
	})
	r.memoryCSV.Flush()
}

type monitoredProcess struct {
	role       string
	process    *xrayProcess
	metricsURL string
}

func (r *reporter) monitor(ctx context.Context, mode string, phase *phaseValue, interval time.Duration, processes ...monitoredProcess) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		for _, process := range processes {
			if err := process.process.exitError(); err != nil {
				return fmt.Errorf("%s process exited during monitoring: %w", process.role, err)
			}
			record, err := sampleProcess(ctx, mode, phase.Load(), process)
			if err != nil {
				record.Error = err.Error()
				r.addMemory(record)
				return fmt.Errorf("monitor %s: %w", process.role, err)
			}
			r.addMemory(record)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func sampleProcess(ctx context.Context, mode, phase string, monitored monitoredProcess) (memoryRecord, error) {
	record := memoryRecord{Timestamp: time.Now(), Mode: mode, Phase: phase, Role: monitored.role, PID: monitored.process.pid()}
	command := exec.CommandContext(ctx, "ps", "-o", "rss=", "-o", "vsz=", "-o", "%cpu=", "-p", strconv.Itoa(record.PID))
	output, err := command.Output()
	if err != nil {
		return record, fmt.Errorf("ps: %w", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 3 {
		return record, fmt.Errorf("unexpected ps output %q", strings.TrimSpace(string(output)))
	}
	if record.RSSKiB, err = strconv.ParseInt(fields[0], 10, 64); err != nil {
		return record, err
	}
	if record.VSZKiB, err = strconv.ParseInt(fields[1], 10, 64); err != nil {
		return record, err
	}
	if record.CPUPercent, err = strconv.ParseFloat(strings.ReplaceAll(fields[2], ",", "."), 64); err != nil {
		return record, err
	}
	runtimeStats, err := readRuntimeStats(ctx, monitored.metricsURL)
	if err != nil {
		return record, err
	}
	record.HeapAlloc = runtimeStats.HeapAlloc
	record.HeapInuse = runtimeStats.HeapInuse
	record.HeapSys = runtimeStats.HeapSys
	record.Sys = runtimeStats.Sys
	record.NumGC = runtimeStats.NumGC
	record.Goroutines = runtimeStats.Goroutines
	return record, nil
}

type runtimeStats struct {
	HeapAlloc  uint64
	HeapInuse  uint64
	HeapSys    uint64
	Sys        uint64
	NumGC      uint32
	Goroutines int
}

func readRuntimeStats(ctx context.Context, baseURL string) (runtimeStats, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/debug/vars", nil)
	if err != nil {
		return runtimeStats{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return runtimeStats{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return runtimeStats{}, fmt.Errorf("debug/vars returned %s", response.Status)
	}
	var vars map[string]json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&vars); err != nil {
		return runtimeStats{}, err
	}
	var mem struct {
		HeapAlloc uint64
		HeapInuse uint64
		HeapSys   uint64
		Sys       uint64
		NumGC     uint32
	}
	if err := json.Unmarshal(vars["memstats"], &mem); err != nil {
		return runtimeStats{}, fmt.Errorf("decode memstats: %w", err)
	}
	stats := runtimeStats{HeapAlloc: mem.HeapAlloc, HeapInuse: mem.HeapInuse, HeapSys: mem.HeapSys, Sys: mem.Sys, NumGC: mem.NumGC}
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/debug/pprof/goroutine?debug=1", nil)
	if err != nil {
		return runtimeStats{}, err
	}
	response, err = client.Do(request)
	if err != nil {
		return runtimeStats{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return runtimeStats{}, fmt.Errorf("goroutine profile returned %s", response.Status)
	}
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	if err != nil {
		return runtimeStats{}, err
	}
	if _, err := fmt.Sscanf(line, "goroutine profile: total %d", &stats.Goroutines); err != nil {
		return runtimeStats{}, fmt.Errorf("parse goroutine count %q: %w", strings.TrimSpace(line), err)
	}
	return stats, nil
}

func (r *reporter) writeSummary() error {
	r.mu.Lock()
	throughput := append([]throughputRecord(nil), r.throughput...)
	memory := append([]memoryRecord(nil), r.memory...)
	checks := append([]checkRecord(nil), r.checks...)
	r.mu.Unlock()

	var builder strings.Builder
	builder.WriteString("# AnyTLS local diagnostic summary\n\n")
	builder.WriteString("## Throughput\n\n")
	builder.WriteString("| Mode | Direction | Concurrency | MiB/s | Direct ratio | Bytes | Transactions |\n")
	builder.WriteString("|---|---:|---:|---:|---:|---:|---:|\n")
	direct := make(map[string]float64)
	for _, record := range throughput {
		if record.Mode == "direct" {
			direct[fmt.Sprintf("%s/%d", record.Direction, record.Concurrency)] = record.MiBPerSecond
		}
	}
	for _, record := range throughput {
		ratio := "-"
		if baseline := direct[fmt.Sprintf("%s/%d", record.Direction, record.Concurrency)]; record.Mode != "direct" && baseline > 0 {
			ratio = fmt.Sprintf("%.2f%%", record.MiBPerSecond/baseline*100)
		}
		fmt.Fprintf(&builder, "| %s | %s | %d | %.2f | %s | %d | %d |\n", record.Mode, record.Direction, record.Concurrency, record.MiBPerSecond, ratio, record.Bytes, record.Transactions)
	}

	builder.WriteString("\n## Correctness checks\n\n")
	if len(checks) == 0 {
		builder.WriteString("No completed checks were recorded.\n")
	} else {
		builder.WriteString("| Mode | Check | Result |\n|---|---|---|\n")
		for _, check := range checks {
			fmt.Fprintf(&builder, "| %s | %s | %s |\n", check.Mode, check.Name, check.Detail)
		}
	}

	builder.WriteString("\n## Memory\n\n")
	builder.WriteString("RSS is process resident memory. Heap values come from Xray's Go runtime metrics.\n\n")
	builder.WriteString("| Mode | Role | Startup RSS KiB | Peak RSS KiB | Final RSS KiB | Final delta KiB | Peak heap MiB | Final goroutines |\n")
	builder.WriteString("|---|---|---:|---:|---:|---:|---:|---:|\n")
	groups := make(map[string][]memoryRecord)
	for _, record := range memory {
		groups[record.Mode+"/"+record.Role] = append(groups[record.Mode+"/"+record.Role], record)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		records := groups[key]
		if len(records) == 0 {
			continue
		}
		startup := records[0]
		final := records[len(records)-1]
		peakRSS := int64(0)
		peakHeap := uint64(0)
		for _, record := range records {
			if strings.Contains(record.Phase, "/startup_idle") {
				startup = record
			}
			if record.RSSKiB > peakRSS {
				peakRSS = record.RSSKiB
			}
			if record.HeapAlloc > peakHeap {
				peakHeap = record.HeapAlloc
			}
		}
		parts := strings.SplitN(key, "/", 2)
		fmt.Fprintf(&builder, "| %s | %s | %d | %d | %d | %+d | %.2f | %d |\n",
			parts[0], parts[1], startup.RSSKiB, peakRSS, final.RSSKiB, final.RSSKiB-startup.RSSKiB, float64(peakHeap)/(1024*1024), final.Goroutines)
	}
	if len(memory) == 0 {
		builder.WriteString("\nNo memory samples were recorded.\n")
	}
	return os.WriteFile(filepath.Join(r.dir, "summary.md"), []byte(builder.String()), 0o600)
}

func (r *reporter) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.throughputCSV.Flush()
	r.memoryCSV.Flush()
	_ = r.events.Close()
	_ = r.throughputFile.Close()
	_ = r.memoryFile.Close()
}

func (h *harness) writeManifest() error {
	serverHash, err := fileSHA256(h.serverBin)
	if err != nil {
		return err
	}
	clientHash, err := fileSHA256(h.clientBin)
	if err != nil {
		return err
	}
	manifest := map[string]any{
		"createdAt":        time.Now().UTC().Format(time.RFC3339Nano),
		"repository":       h.root,
		"commit":           commandText(h.root, "git", "rev-parse", "HEAD"),
		"branch":           commandText(h.root, "git", "branch", "--show-current"),
		"dirtyState":       commandText(h.root, "git", "status", "--short"),
		"goVersion":        commandText(h.root, "go", "version"),
		"buildCommand":     h.buildCommand,
		"serverBinary":     h.serverBin,
		"serverSHA256":     serverHash,
		"clientBinary":     h.clientBin,
		"clientSHA256":     clientHash,
		"duration":         h.opts.duration.String(),
		"concurrency":      h.opts.concurrency,
		"churn":            h.opts.churn,
		"recovery":         h.opts.recovery.String(),
		"sampleInterval":   h.opts.sampleEvery.String(),
		"transferSize":     h.opts.transferSize,
		"integritySize":    h.opts.integritySize,
		"udpPackets":       h.opts.udpPackets,
		"tcpPayloadTarget": h.payload.TCPAddr(),
		"udpPayloadPort":   h.payload.UDPPort(),
		"arguments":        os.Args[1:],
	}
	return writeJSON(filepath.Join(h.resultsDir, "manifest.json"), manifest)
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
	command := exec.Command(name, args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output))
}

var _ = errors.Join
