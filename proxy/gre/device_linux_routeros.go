//go:build routeros_gre && linux

package gre

import (
	"context"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"io"
	"sync"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

type rawDevice struct {
	ctx       context.Context
	cancel    context.CancelFunc
	config    runtimeConfig
	fd        int
	wakeRead  int
	wakeWrite int
	remote    *unix.SockaddrInet4
	ioMu      sync.RWMutex
	readMu    sync.Mutex
	closed    bool
	stopWake  func() bool
	closeOnce sync.Once
	dropMu    sync.Mutex
	dropLast  time.Time
	dropCount uint64
}

func newPacketDevice(ctx context.Context, config runtimeConfig) (packetDevice, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_GRE)
	if err != nil {
		if stderrors.Is(err, syscall.EPERM) || stderrors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("open raw GRE socket (CAP_NET_RAW required): %w", err)
		}
		return nil, fmt.Errorf("open raw GRE socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: config.local.As4()}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind raw GRE socket to %s: %w", config.local, err)
	}
	wake := []int{-1, -1}
	if err := unix.Pipe2(wake, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create GRE shutdown pipe: %w", err)
	}
	deviceCtx, cancel := context.WithCancel(ctx)
	device := &rawDevice{
		ctx: deviceCtx, cancel: cancel, config: config, fd: fd,
		wakeRead: wake[0], wakeWrite: wake[1],
		remote: &unix.SockaddrInet4{Addr: config.remote.As4()},
	}
	device.stopWake = context.AfterFunc(deviceCtx, device.wake)
	return device, nil
}

func (d *rawDevice) Name() (string, error) { return "gre", nil }
func (d *rawDevice) Index() (int, error) {
	return 0, fmt.Errorf("userspace GRE has no kernel interface")
}
func (d *rawDevice) Start() error { return nil }

// ReadPacket hands the validated inner packet directly to the stack. The caller
// owns b and can reuse it after Input returns; no endpoint queue or copy is needed.
func (d *rawDevice) ReadPacket(b []byte) ([]byte, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	d.ioMu.RLock()
	defer d.ioMu.RUnlock()
	if d.closed || d.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	if len(b) < 65535 {
		b = make([]byte, 65535)
	}
	pollFDs := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}, {Fd: int32(d.wakeRead), Events: unix.POLLIN}}
	for {
		_, err := unix.Poll(pollFDs, -1)
		if err != nil {
			if stderrors.Is(err, syscall.EINTR) {
				continue
			}
			return nil, fmt.Errorf("poll raw GRE socket: %w", err)
		}
		if pollFDs[1].Revents != 0 || d.ctx.Err() != nil {
			return nil, io.ErrClosedPipe
		}
		revents := pollFDs[0].Revents
		if revents&(unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil, io.ErrClosedPipe
		}
		if revents&unix.POLLERR != 0 {
			d.logSocketError()
		}
		if revents&unix.POLLIN == 0 {
			continue
		}
		n, from, err := unix.Recvfrom(d.fd, b, 0)
		if err != nil {
			if stderrors.Is(err, syscall.EINTR) || stderrors.Is(err, syscall.EAGAIN) {
				continue
			}
			return nil, fmt.Errorf("receive raw GRE packet: %w", err)
		}
		peer, ok := from.(*unix.SockaddrInet4)
		if !ok || peer.Addr != d.config.remote.As4() {
			d.logDrop("unexpected outer peer", nil)
			continue
		}
		decoded, err := decodeGREDatagram(b[:n], d.config)
		if err != nil {
			d.logDrop("reject GRE packet", err)
			continue
		}
		if decoded.keepaliveReply != nil {
			// ioMu is already held, including while reflecting a keepalive.
			if err := d.sendToRemote([][]byte{decoded.keepaliveReply}); err != nil {
				d.logDrop("reflect RouterOS GRE keepalive", err)
			}
			continue
		}
		return decoded.innerPacket, nil
	}
}

func (d *rawDevice) logSocketError() {
	socketError, err := unix.GetsockoptInt(d.fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		d.logDrop("inspect raw socket poll error", err)
		return
	}
	if socketError == 0 {
		d.logDrop("raw socket reported a recoverable poll error", nil)
		return
	}
	d.logDrop("raw socket reported a recoverable error", syscall.Errno(socketError))
}

// WritePacket sends GRE, IP/transport headers and payload as one datagram.
// The stack already segments TCP and fragments UDP/ICMP to the configured MTU.
func (d *rawDevice) WritePacket(header, payload []byte) error {
	protocol, err := outboundGREProtocolParts(header, len(payload), d.config.mtu)
	if err != nil {
		return err
	}
	var greHeader [4]byte
	binary.BigEndian.PutUint16(greHeader[2:], protocol)
	d.ioMu.RLock()
	defer d.ioMu.RUnlock()
	if d.closed || d.ctx.Err() != nil {
		return io.ErrClosedPipe
	}
	return d.sendToRemote([][]byte{greHeader[:], header, payload})
}

// sendToRemote requires ioMu to be held so Close cannot recycle the socket fd.
func (d *rawDevice) sendToRemote(parts [][]byte) error {
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	for {
		if d.ctx.Err() != nil {
			return io.ErrClosedPipe
		}
		n, err := unix.SendmsgBuffers(d.fd, parts, nil, d.remote, 0)
		if stderrors.Is(err, syscall.EINTR) {
			continue
		}
		if stderrors.Is(err, syscall.EAGAIN) {
			pollFDs := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLOUT}, {Fd: int32(d.wakeRead), Events: unix.POLLIN}}
			for {
				_, err = unix.Poll(pollFDs, -1)
				if !stderrors.Is(err, syscall.EINTR) {
					break
				}
			}
			if err != nil {
				return err
			}
			if pollFDs[1].Revents != 0 || d.ctx.Err() != nil {
				return io.ErrClosedPipe
			}
			if pollFDs[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
				return fmt.Errorf("raw GRE socket failed while waiting to send")
			}
			continue
		}
		if err == nil && n != size {
			return io.ErrShortWrite
		}
		return err
	}
}

func (d *rawDevice) wake() {
	d.ioMu.RLock()
	defer d.ioMu.RUnlock()
	if !d.closed {
		_, _ = unix.Write(d.wakeWrite, []byte{1})
	}
}

func (d *rawDevice) logDrop(reason string, err error) {
	d.dropMu.Lock()
	defer d.dropMu.Unlock()
	d.dropCount++
	if time.Since(d.dropLast) < time.Second {
		return
	}
	if err == nil {
		errors.LogDebug(d.ctx, "[gre] ", reason, "; dropped=", d.dropCount)
	} else {
		errors.LogInfoInner(d.ctx, err, "[gre] ", reason, "; dropped=", d.dropCount)
	}
	d.dropLast = time.Now()
	d.dropCount = 0
}

func (d *rawDevice) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		d.cancel()
		d.stopWake()
		d.wake()
		d.ioMu.Lock()
		defer d.ioMu.Unlock()
		d.closed = true
		for _, fd := range []int{d.fd, d.wakeRead, d.wakeWrite} {
			if err := unix.Close(fd); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}
