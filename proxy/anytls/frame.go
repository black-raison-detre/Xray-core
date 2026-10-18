package anytls

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	CommandWaste byte = iota
	CommandSYN
	CommandPSH
	CommandFIN
	CommandSettings
	CommandAlert
	CommandUpdatePaddingScheme
	CommandSYNACK
	CommandHeartRequest
	CommandHeartResponse
	CommandServerSettings
	maxFrameData = 65535
)

var ErrMalformedFrame = errors.New("anytls: malformed frame")

type Frame struct {
	Command   byte
	SessionID uint32
	Data      []byte
}

func (f Frame) WriteTo(w io.Writer) error {
	if len(f.Data) > maxFrameData {
		return ErrMalformedFrame
	}
	var h [7]byte
	h[0] = f.Command
	binary.BigEndian.PutUint32(h[1:5], f.SessionID)
	binary.BigEndian.PutUint16(h[5:7], uint16(len(f.Data)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	if len(f.Data) == 0 {
		return nil
	}
	_, err := w.Write(f.Data)
	return err
}

func ReadFrame(r io.Reader) (Frame, error) {
	var h [7]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	n := int(binary.BigEndian.Uint16(h[5:7]))
	f := Frame{Command: h[0], SessionID: binary.BigEndian.Uint32(h[1:5])}
	if n != 0 {
		f.Data = make([]byte, n)
		if _, err := io.ReadFull(r, f.Data); err != nil {
			return Frame{}, err
		}
	}
	if f.Command > CommandServerSettings {
		return Frame{}, ErrMalformedFrame
	}
	return f, nil
}
