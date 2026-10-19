package buf

import (
	"syscall"
)

type windowsReader struct {
	bufs  []syscall.WSABuf
	ready bool
}

func (r *windowsReader) Init(bs []*Buffer) {
	if r.bufs == nil {
		r.bufs = make([]syscall.WSABuf, 0, len(bs))
	}
	for _, b := range bs {
		r.bufs = append(r.bufs, syscall.WSABuf{Len: uint32(Size), Buf: &b.v[0]})
	}
	r.ready = false
}

func (r *windowsReader) Clear() {
	for idx := range r.bufs {
		r.bufs[idx].Buf = nil
	}
	r.bufs = r.bufs[:0]
}

func (r *windowsReader) Read(fd uintptr) int32 {
	// WSARecv blocks when called with a nil OVERLAPPED. Let rawConn.Read wait
	// for readability before attempting the receive.
	if !r.ready {
		r.ready = true
		return -1
	}

	var nBytes uint32
	var flags uint32
	err := syscall.WSARecv(syscall.Handle(fd), &r.bufs[0], uint32(len(r.bufs)), &nBytes, &flags, nil, nil)
	if err != nil {
		return -1
	}
	return int32(nBytes)
}

func newMultiReader() multiReader {
	return new(windowsReader)
}
