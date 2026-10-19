//go:build routeros_gre && linux

package gre

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Use an ordinary datagram socket: shutdown must work without CAP_NET_RAW or a
// RouterOS device. The same poll/wake path is used by the production raw socket.
func TestRawDeviceCloseUnblocksRead(t *testing.T) {
	for _, cancelContext := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelContext), func(t *testing.T) {
			sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(sockets[1])
			wake := []int{-1, -1}
			if err := unix.Pipe2(wake, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
				unix.Close(sockets[0])
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			d := &rawDevice{ctx: ctx, cancel: cancel, fd: sockets[0], wakeRead: wake[0], wakeWrite: wake[1]}
			d.stopWake = context.AfterFunc(ctx, d.wake)
			defer d.Close()
			readDone := make(chan error, 1)
			go func() { _, err := d.ReadPacket(make([]byte, 65535)); readDone <- err }()
			select {
			case err := <-readDone:
				t.Fatalf("read returned before shutdown: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
			closed := make(chan error, 1)
			if cancelContext {
				cancel()
			} else {
				go func() { closed <- d.Close() }()
			}
			select {
			case err := <-readDone:
				if !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("read error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("shutdown did not unblock ReadPacket")
			}
			if !cancelContext {
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("Close blocked")
				}
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := d.ReadPacket(nil); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("read after close = %v", err)
			}
		})
	}
}
