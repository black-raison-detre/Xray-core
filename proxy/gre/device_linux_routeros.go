//go:build routeros_gre && linux

package gre

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type rawDevice struct {
	ctx       context.Context
	cancel    context.CancelFunc
	config    runtimeConfig
	fd        int
	wakeRead  int
	wakeWrite int
	endpoint  *channel.Endpoint
	remote    *unix.SockaddrInet4
	wg        sync.WaitGroup
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
	return &rawDevice{
		ctx: deviceCtx, cancel: cancel, config: config, fd: fd,
		wakeRead: wake[0], wakeWrite: wake[1],
		endpoint: channel.New(1024, config.mtu, ""),
		remote:   &unix.SockaddrInet4{Addr: config.remote.As4()},
	}, nil
}

func (d *rawDevice) Endpoint() stack.LinkEndpoint { return d.endpoint }

func (d *rawDevice) Start() error {
	d.wg.Add(2)
	go d.receiveLoop()
	go d.sendLoop()
	return nil
}

func (d *rawDevice) receiveLoop() {
	defer d.wg.Done()
	pollFDs := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}, {Fd: int32(d.wakeRead), Events: unix.POLLIN}}
	bufferBytes := make([]byte, 65535)
	for {
		_, err := unix.Poll(pollFDs, -1)
		if err != nil {
			if stderrors.Is(err, syscall.EINTR) {
				continue
			}
			d.logDrop("poll raw socket", err)
			return
		}
		if pollFDs[1].Revents != 0 || d.ctx.Err() != nil {
			return
		}
		if pollFDs[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			d.logDrop("raw socket poll failure", nil)
			return
		}
		if pollFDs[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, from, err := unix.Recvfrom(d.fd, bufferBytes, 0)
		if err != nil {
			if stderrors.Is(err, syscall.EINTR) || stderrors.Is(err, syscall.EAGAIN) {
				continue
			}
			d.logDrop("receive raw packet", err)
			return
		}
		peer, ok := from.(*unix.SockaddrInet4)
		if !ok || peer.Addr != d.config.remote.As4() {
			d.logDrop("unexpected outer peer", nil)
			continue
		}
		decoded, err := decodeGREDatagram(bufferBytes[:n], d.config)
		if err != nil {
			d.logDrop("reject GRE packet", err)
			continue
		}
		if decoded.keepaliveReply != nil {
			if err := d.sendToRemote(decoded.keepaliveReply); err != nil {
				d.logDrop("reflect RouterOS GRE keepalive", err)
			}
			continue
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), decoded.innerIPv4...))})
		d.endpoint.InjectInbound(header.IPv4ProtocolNumber, packet)
		packet.DecRef()
	}
}

func (d *rawDevice) sendLoop() {
	defer d.wg.Done()
	for {
		packet := d.endpoint.ReadContext(d.ctx)
		if packet == nil {
			return
		}
		view := packet.ToView()
		packet.DecRef()
		fragments, err := fragmentIPv4Packet(view.AsSlice(), d.config.mtu)
		view.Release()
		if err != nil {
			d.logDrop("reject outbound packet", err)
			continue
		}
		for _, fragment := range fragments {
			grePacket, err := encodeGREPacket(fragment, d.config.mtu)
			if err != nil {
				d.logDrop("encode outbound GRE packet", err)
				break
			}
			err = d.sendToRemote(grePacket)
			if err != nil {
				d.logDrop("send GRE packet", err)
				break
			}
		}
	}
}

func (d *rawDevice) sendToRemote(payload []byte) error {
	for {
		err := unix.Sendto(d.fd, payload, 0, d.remote)
		if !stderrors.Is(err, syscall.EINTR) {
			return err
		}
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
		_, _ = unix.Write(d.wakeWrite, []byte{1})
		d.wg.Wait()
		d.endpoint.Close()
		for _, fd := range []int{d.fd, d.wakeRead, d.wakeWrite} {
			if err := unix.Close(fd); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}
