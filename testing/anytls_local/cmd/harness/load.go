package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type transferDirection string

const (
	directionDownload transferDirection = "download"
	directionUpload   transferDirection = "upload"
)

type payloadServer struct {
	tcpListener *net.TCPListener
	udpConn     *net.UDPConn
	cancel      context.CancelFunc
	closeOnce   sync.Once
	wg          sync.WaitGroup
}

func startPayloadServer(parent context.Context) (*payloadServer, error) {
	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	server := &payloadServer{tcpListener: tcpListener, udpConn: udpConn, cancel: cancel}
	server.wg.Add(2)
	go server.serveTCP(ctx)
	go server.serveUDP(ctx)
	return server, nil
}

func (s *payloadServer) TCPAddr() string { return s.tcpListener.Addr().String() }
func (s *payloadServer) UDPPort() int    { return s.udpConn.LocalAddr().(*net.UDPAddr).Port }

func (s *payloadServer) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.tcpListener.Close()
		_ = s.udpConn.Close()
		s.wg.Wait()
	})
}

func (s *payloadServer) serveTCP(ctx context.Context) {
	defer s.wg.Done()
	for {
		conn, err := s.tcpListener.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			_ = handlePayloadConnection(conn)
		}()
	}
}

func handlePayloadConnection(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	reader := bufio.NewReader(conn)
	header, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	fields := strings.Fields(header)
	if len(fields) != 2 {
		return fmt.Errorf("invalid payload command %q", header)
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || size < 0 {
		return fmt.Errorf("invalid payload size %q", fields[1])
	}
	switch fields[0] {
	case "DOWNLOAD":
		return writePattern(conn, size)
	case "UPLOAD":
		if err := readAndValidatePattern(reader, size); err != nil {
			return err
		}
		_, err = fmt.Fprintf(conn, "OK %d\n", size)
		return err
	case "ECHO":
		if err := readAndValidatePattern(reader, size); err != nil {
			return err
		}
		return writePattern(conn, size)
	default:
		return fmt.Errorf("unknown payload command %q", fields[0])
	}
}

func (s *payloadServer) serveUDP(ctx context.Context) {
	defer s.wg.Done()
	buffer := make([]byte, 64<<10)
	for {
		_ = s.udpConn.SetReadDeadline(time.Now().Add(time.Second))
		n, address, err := s.udpConn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			continue
		}
		_, _ = s.udpConn.WriteToUDP(buffer[:n], address)
	}
}

func fillPattern(buffer []byte, offset int64) {
	for i := range buffer {
		buffer[i] = byte(((offset+int64(i))*31 + 17) % 251)
	}
}

func writePattern(writer io.Writer, size int64) error {
	buffer := make([]byte, 64<<10)
	var offset int64
	for offset < size {
		length := int64(len(buffer))
		if remaining := size - offset; remaining < length {
			length = remaining
		}
		fillPattern(buffer[:length], offset)
		written, err := writer.Write(buffer[:length])
		if err != nil {
			return err
		}
		if int64(written) != length {
			return io.ErrShortWrite
		}
		offset += length
	}
	return nil
}

func readAndValidatePattern(reader io.Reader, size int64) error {
	buffer := make([]byte, 64<<10)
	expected := make([]byte, len(buffer))
	var offset int64
	for offset < size {
		length := int64(len(buffer))
		if remaining := size - offset; remaining < length {
			length = remaining
		}
		if _, err := io.ReadFull(reader, buffer[:length]); err != nil {
			return err
		}
		fillPattern(expected[:length], offset)
		if !bytes.Equal(buffer[:length], expected[:length]) {
			return fmt.Errorf("payload mismatch at offset %d", offset)
		}
		offset += length
	}
	return nil
}

func runFixedLoad(ctx context.Context, target, socks string, direction transferDirection, concurrency int, size int64) error {
	start := make(chan struct{})
	errCh := make(chan error, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-start:
			}
			if err := transferOnce(ctx, target, socks, direction, size); err != nil {
				errCh <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	return combineErrors(errCh)
}

func runTimedLoad(ctx context.Context, target, socks string, direction transferDirection, concurrency int, duration time.Duration, transactionSize int64) (throughputRecord, error) {
	startGate := make(chan struct{})
	errCh := make(chan error, concurrency)
	var wg sync.WaitGroup
	var totalBytes atomic.Int64
	var transactions atomic.Int64
	start := time.Now()
	deadline := start.Add(duration)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-startGate:
			}
			for time.Now().Before(deadline) {
				if err := transferOnce(ctx, target, socks, direction, transactionSize); err != nil {
					errCh <- err
					return
				}
				totalBytes.Add(transactionSize)
				transactions.Add(1)
			}
		}()
	}
	start = time.Now()
	deadline = start.Add(duration)
	close(startGate)
	wg.Wait()
	elapsed := time.Since(start)
	close(errCh)
	if err := combineErrors(errCh); err != nil {
		return throughputRecord{}, err
	}
	if totalBytes.Load() == 0 {
		return throughputRecord{}, errors.New("timed load completed without transferring payload bytes")
	}
	return throughputRecord{
		Direction:    string(direction),
		Concurrency:  concurrency,
		Bytes:        totalBytes.Load(),
		Transactions: transactions.Load(),
		Elapsed:      elapsed,
		MiBPerSecond: float64(totalBytes.Load()) / (1024 * 1024) / elapsed.Seconds(),
	}, nil
}

func runChurn(ctx context.Context, target, socks string, concurrency, count int, size int64) error {
	if count == 0 {
		return nil
	}
	var next atomic.Int64
	errCh := make(chan error, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				index := int(next.Add(1))
				if index > count {
					return
				}
				if err := echoOnce(ctx, target, socks, size); err != nil {
					errCh <- fmt.Errorf("round trip %d: %w", index, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	return combineErrors(errCh)
}

func transferOnce(ctx context.Context, target, socks string, direction transferDirection, size int64) error {
	conn, err := dialTarget(ctx, target, socks)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	switch direction {
	case directionDownload:
		if _, err := fmt.Fprintf(conn, "DOWNLOAD %d\n", size); err != nil {
			return err
		}
		return readAndValidatePattern(conn, size)
	case directionUpload:
		if _, err := fmt.Fprintf(conn, "UPLOAD %d\n", size); err != nil {
			return err
		}
		if err := writePattern(conn, size); err != nil {
			return err
		}
		ack, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(ack) != fmt.Sprintf("OK %d", size) {
			return fmt.Errorf("invalid upload acknowledgement %q", strings.TrimSpace(ack))
		}
		return nil
	default:
		return fmt.Errorf("unsupported transfer direction %q", direction)
	}
}

func echoOnce(ctx context.Context, target, socks string, size int64) error {
	conn, err := dialTarget(ctx, target, socks)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprintf(conn, "ECHO %d\n", size); err != nil {
		return err
	}
	if err := writePattern(conn, size); err != nil {
		return err
	}
	return readAndValidatePattern(conn, size)
}

func dialTarget(ctx context.Context, target, socks string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	if socks == "" {
		return dialer.DialContext(ctx, "tcp4", target)
	}
	conn, err := dialer.DialContext(ctx, "tcp4", socks)
	if err != nil {
		return nil, err
	}
	if err := socks5Connect(conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func socks5Connect(conn net.Conn, target string) error {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != 0 {
		return fmt.Errorf("SOCKS5 authentication reply %v", reply)
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid target port %q", portText)
	}
	ip := net.ParseIP(host)
	request := []byte{5, 1, 0}
	if ipv4 := ip.To4(); ipv4 != nil {
		request = append(request, 1)
		request = append(request, ipv4...)
	} else if ipv6 := ip.To16(); ipv6 != nil {
		request = append(request, 4)
		request = append(request, ipv6...)
	} else {
		if len(host) > 255 {
			return errors.New("SOCKS5 hostname is too long")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		return err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 0 {
		return fmt.Errorf("SOCKS5 connect reply code %d", header[1])
	}
	var addressLength int
	switch header[3] {
	case 1:
		addressLength = 4
	case 4:
		addressLength = 16
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		addressLength = int(length[0])
	default:
		return fmt.Errorf("SOCKS5 invalid address type %d", header[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressLength+2)); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}

func runUDPSmoke(ctx context.Context, target string, count int) error {
	if count == 0 {
		return nil
	}
	remote, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		return err
	}
	defer conn.Close()
	request := make([]byte, 1024)
	response := make([]byte, len(request))
	for sequence := 0; sequence < count; sequence++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		binary.BigEndian.PutUint32(request[:4], uint32(sequence))
		fillPattern(request[4:], int64(sequence)*int64(len(request)))
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(request); err != nil {
			return err
		}
		n, err := io.ReadFull(conn, response)
		if err != nil {
			return fmt.Errorf("datagram %d: %w", sequence, err)
		}
		if n != len(request) || !bytes.Equal(request, response) {
			return fmt.Errorf("datagram %d mismatch", sequence)
		}
	}
	return nil
}

func combineErrors(errorsChannel <-chan error) error {
	var combined []error
	for err := range errorsChannel {
		if err != nil {
			combined = append(combined, err)
		}
	}
	return errors.Join(combined...)
}
