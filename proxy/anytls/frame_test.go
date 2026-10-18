package anytls

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	want := Frame{Command: CommandPSH, SessionID: 0x01020304, Data: []byte("ok")}
	if e := want.WriteTo(&b); e != nil {
		t.Fatal(e)
	}
	got, e := ReadFrame(&b)
	if e != nil || got.Command != want.Command || got.SessionID != want.SessionID || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("got %#v, %v", got, e)
	}
}

func TestFrameRejectsUnknownCommand(t *testing.T) {
	_, e := ReadFrame(bytes.NewReader([]byte{99, 0, 0, 0, 0, 0, 0}))
	if !errors.Is(e, ErrMalformedFrame) {
		t.Fatalf("got %v", e)
	}
}

func TestFrameShort(t *testing.T) {
	_, e := ReadFrame(bytes.NewReader([]byte{1}))
	if !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", e)
	}
}
