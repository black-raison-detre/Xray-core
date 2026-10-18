package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type xrayProcess struct {
	cmd    *exec.Cmd
	log    *os.File
	exited chan struct{}
	mu     sync.Mutex
	err    error
}

func validateConfig(ctx context.Context, binary, config string) error {
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

func startXray(binary, config, logPath string) (*xrayProcess, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binary, "run", "-c", config)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	p := &xrayProcess{cmd: cmd, log: logFile, exited: make(chan struct{})}
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

func (p *xrayProcess) pid() int {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *xrayProcess) exitError() error {
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

func (p *xrayProcess) stop() error {
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
		return errors.New("Xray did not stop after SIGTERM and was killed")
	}
}

func waitForMetrics(ctx context.Context, process *xrayProcess, baseURL string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	client := &http.Client{Timeout: time.Second}
	for {
		if err := process.exitError(); err != nil {
			return fmt.Errorf("process exited: %w", err)
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
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
