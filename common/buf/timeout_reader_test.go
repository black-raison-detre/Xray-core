package buf_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type blockedMultiBufferReader struct {
	started chan struct{}
	release chan struct{}
	mb      buf.MultiBuffer
}

func (r *blockedMultiBufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	close(r.started)
	<-r.release
	return r.mb, nil
}

func TestTimeoutWrapperReaderPreservesPayloadAfterTimeout(t *testing.T) {
	payload := []byte("pending payload")
	reader := &blockedMultiBufferReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
		mb:      buf.MultiBuffer{buf.FromBytes(payload)},
	}
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(reader.release) })

	timeoutReader := &buf.TimeoutWrapperReader{Reader: reader}
	mb, err := timeoutReader.ReadMultiBufferTimeout(20 * time.Millisecond)
	if err != buf.ErrReadTimeout {
		t.Fatalf("ReadMultiBufferTimeout() error = %v, want %v", err, buf.ErrReadTimeout)
	}
	if len(mb) != 0 {
		t.Fatalf("ReadMultiBufferTimeout() returned %d buffers on timeout, want none", len(mb))
	}

	<-reader.started
	releaseOnce.Do(func() { close(reader.release) })

	mb, err = timeoutReader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v, want nil", err)
	}
	defer buf.ReleaseMulti(mb)
	got := make([]byte, mb.Len())
	mb.Copy(got)
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadMultiBuffer() payload = %q, want %q", got, payload)
	}
}
