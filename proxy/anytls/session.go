package anytls

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/anytls/internal/pipe"
)

var (
	ErrSessionClosed = errors.New("anytls: session closed")
	ErrProtocol      = errors.New("anytls: protocol violation")
)

// Session owns the framing state for one authenticated AnyTLS connection.
// Version is the peer's advertised version; the zero-value peer is v1.
type Session struct {
	rw             io.ReadWriteCloser
	writeMu        sync.Mutex
	controlMu      sync.Mutex // serializes shared transport deadline changes
	deadlineMu     sync.Mutex // prevents a concurrent write from undoing shutdown
	streams        sync.Map
	nextID         atomic.Uint32
	closed         atomic.Bool
	version        atomic.Uint32
	negotiation    atomic.Uint32 // 0 unknown, 1 legacy v1, 2 negotiated v2
	negotiated     chan struct{}
	negotiatedOnce sync.Once
	server         bool
	onStream       func(*Stream)
	settings       atomic.Bool
	padding        atomic.Pointer[PaddingFactory]
	onPadding      func(*PaddingFactory)
	onClose        func() // installed before Serve; releases transport context
	packet         uint32
	pending        []Frame // client SETTINGS/SYN are deliberately coalesced with first PSH
}

func NewSession(rw io.ReadWriteCloser) *Session {
	s := &Session{rw: rw, negotiated: make(chan struct{})}
	s.version.Store(1)
	return s
}

func NewServerSession(rw io.ReadWriteCloser, onStream func(*Stream)) *Session {
	s := NewSession(rw)
	s.server = true
	s.onStream = onStream
	return s
}
func (s *Session) Version() uint32 { return s.version.Load() }
func (s *Session) SetVersion(v uint32) {
	if v == 1 || v == 2 {
		s.version.Store(v)
	}
}

func (s *Session) markV2Negotiated() {
	s.SetVersion(2)
	s.negotiation.Store(2)
	s.negotiatedOnce.Do(func() { close(s.negotiated) })
}

func (s *Session) markLegacyNegotiated() {
	if s.negotiation.CompareAndSwap(0, 1) {
		s.negotiatedOnce.Do(func() { close(s.negotiated) })
	}
}
func (s *Session) SetPaddingCallback(fn func(*PaddingFactory)) { s.onPadding = fn }
func (s *Session) Padding() *PaddingFactory                    { return s.padding.Load() }

func (s *Session) StartClient(p *PaddingFactory) error {
	if p == nil {
		p = DefaultPaddingFactory()
	}
	s.padding.Store(p)
	s.settings.Store(true) // v1 servers never send ServerSettings.
	return s.queue(Frame{Command: CommandSettings, Data: clientSettings(p)})
}

// StartServer emits exactly the v2 server capability record.  It is called
// only after a valid v2 client Settings frame has been accepted.
func (s *Session) StartServer(_ *PaddingFactory) error {
	return s.write(Frame{Command: CommandServerSettings, Data: []byte("v=2")})
}

func (s *Session) UpdatePadding(p *PaddingFactory) error {
	if p == nil {
		return ErrMalformedFrame
	}
	return s.write(Frame{Command: CommandUpdatePaddingScheme, Data: p.RawScheme()})
}

// AcceptStream releases a v2 client after its destination was accepted.
func (s *Session) AcceptStream(st *Stream) error {
	if st == nil || !s.server || s.Version() < 2 {
		return nil
	}
	return s.write(Frame{Command: CommandSYNACK, SessionID: st.id})
}

// RejectStream terminates a stream which was not accepted by the server.
func (s *Session) RejectStream(st *Stream, causes ...error) error {
	if st == nil || !s.server {
		return ErrProtocol
	}
	if s.Version() >= 2 {
		message := "request rejected"
		if len(causes) > 0 && causes[0] != nil {
			message = causes[0].Error()
		}
		if len(message) > maxFrameData {
			message = message[:maxFrameData]
		}
		if err := s.write(Frame{Command: CommandSYNACK, SessionID: st.id, Data: []byte(message)}); err != nil {
			return err
		}
	}
	return st.Close()
}

// AckStream is retained for existing handlers; new handlers should make their
// disposition explicit with AcceptStream or RejectStream.
func (s *Session) AckStream(st *Stream) error { return s.AcceptStream(st) }

func (s *Session) NewStream() (*Stream, error) {
	return s.newStreamWithClose(nil)
}

func (s *Session) newStreamWithClose(onClose func()) (*Stream, error) {
	if s.closed.Load() || !s.settings.Load() {
		return nil, ErrSessionClosed
	}
	id := s.nextID.Add(1)
	if id == 0 {
		return nil, ErrSessionClosed
	}
	st := newStream(s, id)
	st.onClose = onClose
	s.streams.Store(id, st)
	var err error
	if s.server {
		err = s.write(Frame{Command: CommandSYN, SessionID: id})
	} else if id == 1 {
		err = s.queue(Frame{Command: CommandSYN, SessionID: id})
	} else {
		err = s.write(Frame{Command: CommandSYN, SessionID: id})
	}
	if err != nil {
		s.streams.Delete(id)
		return nil, err
	}
	return st, nil
}

func (s *Session) queue(f Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return ErrSessionClosed
	}
	s.pending = append(s.pending, f)
	return nil
}

func (s *Session) write(f Frame) error {
	// Upstream v0.0.13 arms this before waiting for the transport mutex:
	// a control frame must also interrupt an already blocked data write.
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	s.deadlineMu.Lock()
	if s.closed.Load() {
		s.deadlineMu.Unlock()
		return ErrSessionClosed
	}
	if d, ok := s.rw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = d.SetWriteDeadline(time.Now().Add(5 * time.Second))
	}
	s.deadlineMu.Unlock()
	s.writeMu.Lock()
	err := s.writeLocked([]Frame{f}, !s.server)
	s.writeMu.Unlock()
	if err != nil {
		_ = s.Close()
	} else {
		s.deadlineMu.Lock()
		if d, ok := s.rw.(interface{ SetWriteDeadline(time.Time) error }); ok && !s.closed.Load() {
			_ = d.SetWriteDeadline(time.Time{})
		}
		s.deadlineMu.Unlock()
	}
	return err
}

func encodeFrames(frames []Frame) ([]byte, error) {
	var b bytes.Buffer
	for _, f := range frames {
		if err := f.WriteTo(&b); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func (s *Session) writeLocked(frames []Frame, shaped bool) error {
	if s.closed.Load() {
		return ErrSessionClosed
	}
	if len(s.pending) != 0 {
		frames = append(append([]Frame(nil), s.pending...), frames...)
		s.pending = nil
	}
	b, err := encodeFrames(frames)
	if err != nil {
		return err
	}
	if !shaped || s.server {
		return writeAll(s.rw, b)
	}
	return s.writeShapedLocked(b)
}

func (s *Session) writeShapedLocked(b []byte) error {
	p := s.Padding()
	if p == nil {
		return writeAll(s.rw, b)
	}
	s.packet++
	for _, target := range p.RecordSizes(s.packet) {
		if target == paddingContinue {
			if len(b) == 0 {
				break
			}
			continue
		}
		if len(b) > target {
			if err := writeAll(s.rw, b[:target]); err != nil {
				return err
			}
			b = b[target:]
			continue
		}
		if len(b) > 0 {
			wasteLen := target - len(b) - 7
			if wasteLen > 0 {
				var record bytes.Buffer
				record.Write(b)
				if err := (Frame{Command: CommandWaste, Data: make([]byte, wasteLen)}).WriteTo(&record); err != nil {
					return err
				}
				b = record.Bytes()
			}
			if err := writeAll(s.rw, b); err != nil {
				return err
			}
		} else {
			var record bytes.Buffer
			if err := (Frame{Command: CommandWaste, Data: make([]byte, target)}).WriteTo(&record); err != nil {
				return err
			}
			if err := writeAll(s.rw, record.Bytes()); err != nil {
				return err
			}
		}
		b = nil
	}
	if len(b) > 0 {
		return writeAll(s.rw, b)
	}
	return nil
}

func (s *Session) Close() error {
	s.deadlineMu.Lock()
	if s.closed.Swap(true) {
		s.deadlineMu.Unlock()
		return nil
	}
	// Interrupt blocked TLS writes before Close tries to send close_notify.
	if d, ok := s.rw.(interface{ SetDeadline(time.Time) error }); ok {
		_ = d.SetDeadline(time.Now())
	}
	s.deadlineMu.Unlock()
	if s.onClose != nil {
		s.onClose()
	}
	s.streams.Range(func(_, v any) bool { v.(*Stream).closeRemote(); return true })
	return s.rw.Close()
}

func invalid(s *Session) error { _ = s.Close(); return ErrProtocol }
func (s *Session) Serve() error {
	defer s.Close()
	for {
		f, err := ReadFrame(s.rw)
		if err != nil {
			_ = s.Close()
			return err
		}
		switch f.Command {
		case CommandSettings:
			if !s.server || s.settings.Load() || f.SessionID != 0 {
				return invalid(s)
			}
			m, err := validateClientSettings(f.Data)
			if err != nil {
				return invalid(s)
			}
			v, _ := strconvVersion(m["v"])
			s.SetVersion(v)
			s.settings.Store(true)
			if v >= 2 {
				if err := s.StartServer(nil); err != nil {
					return err
				}
			}
			if p := s.Padding(); p != nil && m["padding-md5"] != p.MD5() {
				if err := s.UpdatePadding(p); err != nil {
					return err
				}
			}
		case CommandServerSettings:
			if s.server || !s.settings.Load() || f.SessionID != 0 || s.Version() == 2 {
				return invalid(s)
			}
			m, err := parseSettings(f.Data)
			if err != nil || len(m) != 1 || m["v"] != "2" {
				return invalid(s)
			}
			s.markV2Negotiated()
		case CommandUpdatePaddingScheme:
			if s.server || !s.settings.Load() || f.SessionID != 0 {
				return invalid(s)
			}
			p, err := NewPaddingFactory(f.Data)
			if err != nil {
				return invalid(s)
			}
			if s.onPadding != nil {
				s.onPadding(p)
			}
		case CommandSYN:
			if !s.server || !s.settings.Load() || f.SessionID == 0 || len(f.Data) != 0 {
				return invalid(s)
			}
			st := newStream(s, f.SessionID)
			if _, loaded := s.streams.LoadOrStore(f.SessionID, st); loaded {
				return invalid(s)
			}
			if s.onStream != nil {
				go s.onStream(st)
			}
		case CommandSYNACK:
			if s.server || s.Version() != 2 || f.SessionID == 0 {
				return invalid(s)
			}
			st, ok := s.streams.Load(f.SessionID)
			if !ok {
				continue // a stream can close before its admission reply arrives
			}
			st.(*Stream).ack(f.Data)
		case CommandPSH:
			if f.SessionID == 0 || len(f.Data) == 0 {
				return invalid(s)
			}
			st, ok := s.streams.Load(f.SessionID)
			if !ok {
				continue // discard data already in flight when a stream closed
			}
			st.(*Stream).deliver(f.Data)
		case CommandFIN:
			if f.SessionID == 0 || len(f.Data) != 0 {
				return invalid(s)
			}
			st, ok := s.streams.LoadAndDelete(f.SessionID)
			if !ok {
				continue // simultaneous local and remote FIN is normal
			}
			st.(*Stream).closeRemote()
		case CommandWaste:
			if f.SessionID != 0 {
				return invalid(s)
			}
		case CommandHeartRequest:
			if f.SessionID != 0 || len(f.Data) != 0 {
				return invalid(s)
			}
			if err := s.write(Frame{Command: CommandHeartResponse}); err != nil {
				return err
			}
		case CommandHeartResponse:
			if f.SessionID != 0 || len(f.Data) != 0 {
				return invalid(s)
			}
		case CommandAlert:
			_ = s.Close()
			return errors.New("anytls: peer alert")
		default:
			return invalid(s)
		}
	}
}

func strconvVersion(v string) (uint32, bool) {
	if v == "1" {
		return 1, true
	}
	if v == "2" {
		return 2, true
	}
	return 0, false
}

func (s *Session) WaitV2(d time.Duration) bool {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	for s.Version() != 2 {
		select {
		case <-deadline.C:
			return false
		case <-time.After(time.Millisecond):
		}
	}
	return true
}

type Stream struct {
	s             *Session
	id            uint32
	pipeR         *pipe.PipeReader
	pipeW         *pipe.PipeWriter
	writeDeadline pipe.PipeDeadline
	done          chan struct{}
	once          sync.Once
	ackCh         chan struct{}
	ackMu         sync.Mutex
	ackErr        error
	onClose       func()
}

func newStream(s *Session, id uint32) *Stream {
	r, w := pipe.Pipe()
	return &Stream{s: s, id: id, pipeR: r, pipeW: w, writeDeadline: pipe.MakePipeDeadline(), done: make(chan struct{}), ackCh: make(chan struct{})}
}
func (st *Stream) ID() uint32 { return st.id }
func (st *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-st.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	case <-st.done:
		return 0, ErrSessionClosed
	default:
	}
	frames := make([]Frame, 0, (len(p)+maxFrameData-1)/maxFrameData)
	for len(p) > 0 {
		n := len(p)
		if n > maxFrameData {
			n = maxFrameData
		}
		frames = append(frames, Frame{Command: CommandPSH, SessionID: st.id, Data: append([]byte(nil), p[:n]...)})
		p = p[n:]
	}
	st.s.writeMu.Lock()
	err := st.s.writeLocked(frames, true)
	st.s.writeMu.Unlock()
	if err != nil {
		_ = st.s.Close()
		return 0, err
	}
	return sumFrameData(frames), nil
}

func sumFrameData(fs []Frame) int {
	n := 0
	for _, f := range fs {
		n += len(f.Data)
	}
	return n
}

func (st *Stream) Read(p []byte) (int, error) {
	return st.pipeR.Read(p)
}

func (st *Stream) Close() error {
	var closed bool
	st.once.Do(func() {
		close(st.done)
		_ = st.pipeR.Close()
		st.s.streams.Delete(st.id)
		closed = true
	})
	if closed {
		// Keep callbacks outside Once: disable-reuse closes the Session and
		// control-write failure may also reenter its stream cleanup.
		err := st.s.write(Frame{Command: CommandFIN, SessionID: st.id})
		if st.onClose != nil {
			st.onClose()
		}
		return err
	}
	return nil
}

func (st *Stream) closeRemote() {
	var closed bool
	st.once.Do(func() {
		close(st.done)
		_ = st.pipeW.Close()
		st.s.streams.Delete(st.id)
		closed = true
	})
	if closed {
		if st.onClose != nil {
			st.onClose()
		}
	}
}

func (st *Stream) deliver(b []byte) {
	// Synchronous delivery is intentional: FIN cannot overtake unread PSH.
	_, _ = st.pipeW.Write(b)
}

func (st *Stream) SetReadDeadline(t time.Time) error { return st.pipeR.SetReadDeadline(t) }

// SetWriteDeadline retains upstream's pre-write deadline check. In-flight
// transport writes are interrupted by control-write deadlines or Session.Close.
func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.writeDeadline.Set(t)
	return nil
}

func (st *Stream) SetDeadline(t time.Time) error {
	_ = st.SetWriteDeadline(t)
	return st.SetReadDeadline(t)
}

func (st *Stream) LocalAddr() net.Addr {
	if c, ok := st.s.rw.(interface{ LocalAddr() net.Addr }); ok {
		return c.LocalAddr()
	}
	return nil
}

func (st *Stream) RemoteAddr() net.Addr {
	if c, ok := st.s.rw.(interface{ RemoteAddr() net.Addr }); ok {
		return c.RemoteAddr()
	}
	return nil
}

func (st *Stream) ack(data []byte) {
	st.ackMu.Lock()
	if len(data) > 0 {
		st.ackErr = errors.New(string(data))
	}
	st.ackMu.Unlock()
	select {
	case <-st.ackCh:
	default:
		close(st.ackCh)
	}
}

func (st *Stream) WaitSYNACK(d time.Duration) bool {
	return st.WaitSYNACKError(d) == nil
}

func (st *Stream) WaitSYNACKError(d time.Duration) error {
	// SYNACK is a v2-only admission signal.  Keep the protocol timeout fixed
	// even when an older handler passes its historical five-second value.
	if d <= 0 || d > 3*time.Second {
		d = 3 * time.Second
	}
	if st.s.negotiation.Load() == 0 {
		// A v1 server never sends ServerSettings. Probe once per session for
		// the full stuck-tunnel bound, then cache the legacy decision so later
		// streams do not repeat the compatibility delay.
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-st.s.negotiated:
		case <-st.done:
			return ErrSessionClosed
		case <-timer.C:
			st.s.markLegacyNegotiated()
			return nil
		}
	}
	if st.s.negotiation.Load() == 1 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-st.ackCh:
		st.ackMu.Lock()
		err := st.ackErr
		st.ackMu.Unlock()
		return err
	case <-st.done:
		select {
		case <-st.ackCh:
			st.ackMu.Lock()
			err := st.ackErr
			st.ackMu.Unlock()
			return err
		default:
		}
		return ErrSessionClosed
	case <-timer.C:
		_ = st.s.Close()
		return errors.New("anytls: SYNACK timeout")
	}
}
