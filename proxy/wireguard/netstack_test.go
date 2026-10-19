/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package wireguard

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func newTestNetTun(t *testing.T) *netTun {
	t.Helper()

	device, _, _, err := CreateNetTUN(nil, nil, 1500, false)
	if err != nil {
		t.Fatal(err)
	}
	tun := device.(*netTun)
	t.Cleanup(func() {
		defer func() { _ = recover() }()
		_ = tun.Close()
	})
	return tun
}

func TestNetTunReadReturnsClosedOnClose(t *testing.T) {
	tun := newTestNetTun(t)
	readResult := make(chan error, 1)
	go func() {
		_, err := tun.Read([][]byte{make([]byte, 1)}, make([]int, 1), 0)
		readResult <- err
	}()

	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readResult:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read error = %v, want %v", err, os.ErrClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after Close")
	}
}

func TestNetTunWriteNotifyCloseUnblocksWithoutPanic(t *testing.T) {
	tun := newTestNetTun(t)
	// Queue one packet without invoking the registered callback, then exercise
	// the notification callback directly so the unbuffered send can be held.
	tun.ep.RemoveNotify(tun.notifyHandle)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{0x45}),
	})
	var packets stack.PacketBufferList
	packets.PushBack(pkt)
	if n, err := tun.ep.WritePackets(packets); err != nil || n != 1 {
		pkt.DecRef()
		t.Fatalf("WritePackets() = (%d, %v), want (1, nil)", n, err)
	}
	pkt.DecRef()

	writeResult := make(chan any, 1)
	go func() {
		defer func() { writeResult <- recover() }()
		tun.WriteNotify()
	}()
	deadline := time.After(time.Second)
	for tun.ep.NumQueued() != 0 {
		select {
		case <-deadline:
			t.Fatal("WriteNotify did not consume the queued packet")
		default:
			runtime.Gosched()
		}
	}

	closeResult := make(chan struct {
		err      error
		panicked any
	}, 1)
	go func() {
		var result struct {
			err      error
			panicked any
		}
		defer func() {
			result.panicked = recover()
			closeResult <- result
		}()
		result.err = tun.Close()
	}()
	select {
	case result := <-closeResult:
		if result.panicked != nil {
			t.Fatalf("Close panicked: %v", result.panicked)
		}
		if result.err != nil {
			t.Fatal(result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return")
	}
	select {
	case panicked := <-writeResult:
		if panicked != nil {
			t.Fatalf("WriteNotify panicked during Close: %v", panicked)
		}
	case <-time.After(time.Second):
		t.Fatal("WriteNotify remained blocked after Close")
	}

	// Close also owns event-channel teardown and must remain safe if callers
	// invoke it more than once.
	var closePanic any
	func() {
		defer func() { closePanic = recover() }()
		_ = tun.Close()
	}()
	if closePanic != nil {
		t.Fatalf("second Close panicked: %v", closePanic)
	}
}

func TestNetTunReadReleasesView(t *testing.T) {
	tun := newTestNetTun(t)
	tun.incomingPacket = make(chan *buffer.View, 1)

	view := buffer.NewView(12)
	if _, err := view.Write([]byte("packet")); err != nil {
		t.Fatal(err)
	}
	retained := view.Clone()
	defer retained.Release()
	backing := &retained.AsSlice()[0]
	tun.incomingPacket <- view

	if n, err := tun.Read([][]byte{make([]byte, 1)}, make([]int, 1), 0); err != nil || n != 1 {
		t.Fatalf("Read() = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := retained.Write([]byte{'!'}); err != nil {
		t.Fatal(err)
	}
	if got := &retained.AsSlice()[0]; got != backing {
		t.Fatal("consumed view still held a reference and forced a copy-on-write")
	}
}
