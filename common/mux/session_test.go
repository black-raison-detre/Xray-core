package mux_test

import (
	"io"
	"sync"
	"testing"
	"time"

	. "github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestSessionManagerAdd(t *testing.T) {
	m := NewSessionManager()

	s := m.Allocate(&ClientStrategy{}, nil, nil)
	if s.ID != 1 {
		t.Error("id: ", s.ID)
	}
	if m.Size() != 1 {
		t.Error("size: ", m.Size())
	}

	s = m.Allocate(&ClientStrategy{}, nil, nil)
	if s.ID != 2 {
		t.Error("id: ", s.ID)
	}
	if m.Size() != 2 {
		t.Error("size: ", m.Size())
	}

	s = &Session{
		ID: 4,
	}
	m.Add(s)
	if s.ID != 4 {
		t.Error("id: ", s.ID)
	}
	if m.Size() != 3 {
		t.Error("size: ", m.Size())
	}
}

func TestSessionManagerClose(t *testing.T) {
	m := NewSessionManager()
	s := m.Allocate(&ClientStrategy{}, nil, nil)

	if m.CloseIfNoSessionAndIdle(m.Size(), m.Count()) {
		t.Error("able to close")
	}
	m.Remove(false, s.ID)
	if !m.CloseIfNoSessionAndIdle(m.Size(), m.Count()) {
		t.Error("not able to close")
	}
}

func TestSessionManagerAllocateConcurrentClose(t *testing.T) {
	for range 100 {
		m := NewSessionManager()
		input, inputWriter := pipe.New()
		outputReader, output := pipe.New()
		start := make(chan struct{})
		var allocated *Session
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			allocated = m.Allocate(&ClientStrategy{}, input, output)
		}()
		go func() {
			defer workers.Done()
			<-start
			m.Close()
		}()
		close(start)
		workers.Wait()
		if allocated != nil {
			if _, err := input.ReadMultiBufferTimeout(time.Second); err != io.ErrClosedPipe {
				t.Errorf("input error = %v, want io.ErrClosedPipe", err)
			}
			if _, err := outputReader.ReadMultiBufferTimeout(time.Second); err != io.EOF {
				t.Errorf("output error = %v, want io.EOF", err)
			}
		}
		input.Interrupt()
		inputWriter.Close()
		outputReader.Interrupt()
		output.Close()
	}
}
