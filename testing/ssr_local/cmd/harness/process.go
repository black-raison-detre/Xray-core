package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type managedProcess struct {
	role   string
	cmd    *exec.Cmd
	log    *os.File
	exited chan struct{}
	mu     sync.Mutex
	err    error
}

func validateXrayConfig(ctx context.Context, binary, config string) error {
	cmd := exec.CommandContext(ctx, binary, "run", "-test", "-c", config)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(string(output), "Configuration OK") {
		return fmt.Errorf("validation did not report Configuration OK: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func startProcess(role, logPath, binary string, args ...string) (*managedProcess, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	p := &managedProcess{role: role, cmd: cmd, log: logFile, exited: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		_ = logFile.Close()
		close(p.exited)
	}()
	return p, nil
}

func (p *managedProcess) pid() int {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *managedProcess) exitError() error {
	select {
	case <-p.exited:
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.err == nil {
			return errors.New("process exited unexpectedly with status 0")
		}
		return p.err
	default:
		return nil
	}
}

func (p *managedProcess) stop() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	select {
	case <-p.exited:
		return nil
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-p.exited:
		return nil
	case <-time.After(5 * time.Second):
		if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		<-p.exited
		return fmt.Errorf("%s did not stop after SIGTERM and was killed", p.role)
	}
}

func waitForTCP(ctx context.Context, process *managedProcess, address string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := process.exitError(); err != nil {
			return fmt.Errorf("%s exited: %w", process.role, err)
		}
		conn, err := (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, "tcp4", address)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for %s at %s: %w", process.role, address, ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForMetrics(ctx context.Context, process *managedProcess, baseURL string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	client := &http.Client{Timeout: time.Second}
	for {
		if err := process.exitError(); err != nil {
			return fmt.Errorf("%s exited: %w", process.role, err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/debug/vars", nil)
		if err == nil {
			response, requestErr := client.Do(request)
			if requestErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for %s metrics: %w", process.role, ctx.Err())
		case <-ticker.C:
		}
	}
}
