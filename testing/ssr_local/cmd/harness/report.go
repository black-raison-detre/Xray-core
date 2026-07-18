package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
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
	Method       string
	Protocol     string
	Obfs         string
	Direction    string
	Concurrency  int
	Repetition   int
	Bytes        int64
	Transactions int64
	Elapsed      time.Duration
	MiBPerSecond float64
}

type compatibilityRecord struct {
	Mode     string
	Method   string
	Protocol string
	Obfs     string
	Network  string
	Passed   bool
	Detail   string
}

type memoryRecord struct {
	Timestamp    time.Time
	Mode         string
	Phase        string
	Role         string
	PID          int
	RSSKiB       int64
	VSZKiB       int64
	CPUPercent   float64
	RuntimeValid bool
	HeapAlloc    uint64
	HeapInuse    uint64
	HeapSys      uint64
	Sys          uint64
	NumGC        uint32
	Goroutines   int
	Error        string
}

type reporter struct {
	dir               string
	mu                sync.Mutex
	events            *os.File
	throughputFile    *os.File
	throughputCSV     *csv.Writer
	compatibilityFile *os.File
	compatibilityCSV  *csv.Writer
	memoryFile        *os.File
	memoryCSV         *csv.Writer
	throughput        []throughputRecord
	compatibility     []compatibilityRecord
	memory            []memoryRecord
	closed            bool
}

func newReporter(dir string) (*reporter, error) {
	events, err := createResultFile(dir, "events.log")
	if err != nil {
		return nil, err
	}
	throughput, err := createResultFile(dir, "throughput.csv")
	if err != nil {
		_ = events.Close()
		return nil, err
	}
	compatibility, err := createResultFile(dir, "compatibility.csv")
	if err != nil {
		_ = events.Close()
		_ = throughput.Close()
		return nil, err
	}
	memory, err := createResultFile(dir, "memory.csv")
	if err != nil {
		_ = events.Close()
		_ = throughput.Close()
		_ = compatibility.Close()
		return nil, err
	}
	r := &reporter{
		dir: dir, events: events,
		throughputFile: throughput, throughputCSV: csv.NewWriter(throughput),
		compatibilityFile: compatibility, compatibilityCSV: csv.NewWriter(compatibility),
		memoryFile: memory, memoryCSV: csv.NewWriter(memory),
	}
	_ = r.throughputCSV.Write([]string{"mode", "method", "protocol", "obfs", "direction", "concurrency", "repetition", "bytes", "transactions", "elapsed_seconds", "mib_per_second"})
	_ = r.compatibilityCSV.Write([]string{"mode", "method", "protocol", "obfs", "network", "passed", "detail"})
	_ = r.memoryCSV.Write([]string{"timestamp", "mode", "phase", "role", "pid", "rss_kib", "vsz_kib", "cpu_percent", "heap_alloc_bytes", "heap_inuse_bytes", "heap_sys_bytes", "sys_bytes", "num_gc", "goroutines", "error"})
	r.flushUnlocked()
	return r, nil
}

func createResultFile(dir, name string) (*os.File, error) {
	return os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
}

func (r *reporter) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logfUnlocked(format, args...)
}

func (r *reporter) logfUnlocked(format string, args ...any) {
	line := fmt.Sprintf("%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprintf(format, args...))
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
		record.Mode, record.Method, record.Protocol, record.Obfs, record.Direction,
		strconv.Itoa(record.Concurrency), strconv.Itoa(record.Repetition), strconv.FormatInt(record.Bytes, 10),
		strconv.FormatInt(record.Transactions, 10), fmt.Sprintf("%.6f", record.Elapsed.Seconds()), fmt.Sprintf("%.3f", record.MiBPerSecond),
	})
	r.throughputCSV.Flush()
	r.logfUnlocked("throughput mode=%s direction=%s concurrency=%d repetition=%d %.2f MiB/s", record.Mode, record.Direction, record.Concurrency, record.Repetition, record.MiBPerSecond)
}

func (r *reporter) addCompatibility(record compatibilityRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.compatibility = append(r.compatibility, record)
	_ = r.compatibilityCSV.Write([]string{record.Mode, record.Method, record.Protocol, record.Obfs, record.Network, strconv.FormatBool(record.Passed), record.Detail})
	r.compatibilityCSV.Flush()
	r.logfUnlocked("compatibility mode=%s network=%s passed=%t %s", record.Mode, record.Network, record.Passed, record.Detail)
}

func (r *reporter) addMemory(record memoryRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.memory = append(r.memory, record)
	runtimeValues := make([]string, 6)
	if record.RuntimeValid {
		runtimeValues = []string{
			strconv.FormatUint(record.HeapAlloc, 10), strconv.FormatUint(record.HeapInuse, 10), strconv.FormatUint(record.HeapSys, 10),
			strconv.FormatUint(record.Sys, 10), strconv.FormatUint(uint64(record.NumGC), 10), strconv.Itoa(record.Goroutines),
		}
	}
	_ = r.memoryCSV.Write([]string{
		record.Timestamp.UTC().Format(time.RFC3339Nano), record.Mode, record.Phase, record.Role, strconv.Itoa(record.PID),
		strconv.FormatInt(record.RSSKiB, 10), strconv.FormatInt(record.VSZKiB, 10), fmt.Sprintf("%.2f", record.CPUPercent),
		runtimeValues[0], runtimeValues[1], runtimeValues[2], runtimeValues[3], runtimeValues[4], runtimeValues[5], record.Error,
	})
	r.memoryCSV.Flush()
}

func (r *reporter) flushUnlocked() {
	r.throughputCSV.Flush()
	r.compatibilityCSV.Flush()
	r.memoryCSV.Flush()
}

type monitoredProcess struct {
	role       string
	process    *managedProcess
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
				if ctx.Err() != nil {
					return ctx.Err()
				}
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
	if monitored.metricsURL == "" {
		return record, nil
	}
	runtimeStats, err := readRuntimeStats(ctx, monitored.metricsURL)
	if err != nil {
		return record, err
	}
	record.RuntimeValid = true
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
	compatibility := append([]compatibilityRecord(nil), r.compatibility...)
	memory := append([]memoryRecord(nil), r.memory...)
	r.mu.Unlock()

	var builder strings.Builder
	builder.WriteString("# ShadowsocksR local benchmark summary\n\n")
	builder.WriteString("Loopback values measure host-local protocol and CPU overhead, not internet performance.\n\n")
	builder.WriteString("## Compatibility\n\n")
	passed := 0
	for _, record := range compatibility {
		if record.Passed {
			passed++
		}
	}
	fmt.Fprintf(&builder, "%d/%d Xray-to-C smoke checks passed.\n\n", passed, len(compatibility))
	for _, record := range compatibility {
		if !record.Passed {
			fmt.Fprintf(&builder, "- FAIL `%s` %s: %s\n", record.Mode, record.Network, record.Detail)
		}
	}

	builder.WriteString("\n## Throughput\n\n")
	builder.WriteString("| Mode | Method | Protocol | Obfs | Direction | Concurrency | Median MiB/s | Min-Max MiB/s | Direct ratio | Repetitions |\n")
	builder.WriteString("|---|---|---|---|---:|---:|---:|---:|---:|---:|\n")
	type throughputGroup struct {
		prototype throughputRecord
		values    []float64
	}
	groups := make(map[string]*throughputGroup)
	for _, record := range throughput {
		key := fmt.Sprintf("%s/%s/%d", record.Mode, record.Direction, record.Concurrency)
		group := groups[key]
		if group == nil {
			group = &throughputGroup{prototype: record}
			groups[key] = group
		}
		group.values = append(group.values, record.MiBPerSecond)
	}
	direct := make(map[string]float64)
	for _, group := range groups {
		if group.prototype.Mode == "direct" {
			direct[fmt.Sprintf("%s/%d", group.prototype.Direction, group.prototype.Concurrency)] = median(group.values)
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		record := group.prototype
		values := append([]float64(nil), group.values...)
		sort.Float64s(values)
		ratio := "-"
		if record.Mode != "direct" {
			if baseline := direct[fmt.Sprintf("%s/%d", record.Direction, record.Concurrency)]; baseline > 0 {
				ratio = fmt.Sprintf("%.2f%%", median(values)/baseline*100)
			}
		}
		fmt.Fprintf(&builder, "| %s | %s | %s | %s | %s | %d | %.2f | %.2f-%.2f | %s | %d |\n",
			record.Mode, displayValue(record.Method), displayValue(record.Protocol), displayValue(record.Obfs), record.Direction,
			record.Concurrency, median(values), values[0], values[len(values)-1], ratio, len(values))
	}

	builder.WriteString("\n## Memory\n\n")
	builder.WriteString("RSS is process resident memory. Go heap and goroutine values are available only for Xray.\n\n")
	builder.WriteString("| Mode | Role | Startup RSS KiB | Peak RSS KiB | Final RSS KiB | Final delta KiB | Peak heap MiB | Final goroutines |\n")
	builder.WriteString("|---|---|---:|---:|---:|---:|---:|---:|\n")
	memoryGroups := make(map[string][]memoryRecord)
	for _, record := range memory {
		if record.Error != "" {
			continue
		}
		memoryGroups[record.Mode+"/"+record.Role] = append(memoryGroups[record.Mode+"/"+record.Role], record)
	}
	keys = keys[:0]
	for key := range memoryGroups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		records := memoryGroups[key]
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
		peakHeapText, goroutineText := "-", "-"
		if final.RuntimeValid {
			peakHeapText = fmt.Sprintf("%.2f", float64(peakHeap)/(1024*1024))
			goroutineText = strconv.Itoa(final.Goroutines)
		}
		fmt.Fprintf(&builder, "| %s | %s | %d | %d | %d | %+d | %s | %s |\n",
			parts[0], parts[1], startup.RSSKiB, peakRSS, final.RSSKiB, final.RSSKiB-startup.RSSKiB, peakHeapText, goroutineText)
	}
	if len(memory) == 0 {
		builder.WriteString("\nNo memory samples were recorded.\n")
	}
	return os.WriteFile(filepath.Join(r.dir, "summary.md"), []byte(builder.String()), 0o600)
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	values = append([]float64(nil), values...)
	sort.Float64s(values)
	middle := len(values) / 2
	if len(values)%2 == 1 {
		return values[middle]
	}
	return (values[middle-1] + values[middle]) / 2
}

func displayValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func (r *reporter) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.flushUnlocked()
	_ = r.events.Close()
	_ = r.throughputFile.Close()
	_ = r.compatibilityFile.Close()
	_ = r.memoryFile.Close()
}
