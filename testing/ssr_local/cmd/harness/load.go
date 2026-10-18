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
	deadline := time.Now().Add(duration)
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
	start := time.Now()
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

func socks5Greeting(conn net.Conn) error {
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
	return nil
}

func socksAddress(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portText)
	}
	var output []byte
	ip := net.ParseIP(host)
	if ipv4 := ip.To4(); ipv4 != nil {
		output = append(output, 1)
		output = append(output, ipv4...)
	} else if ipv6 := ip.To16(); ipv6 != nil {
		output = append(output, 4)
		output = append(output, ipv6...)
	} else {
		if len(host) > 255 {
			return nil, errors.New("SOCKS5 hostname is too long")
		}
		output = append(output, 3, byte(len(host)))
		output = append(output, host...)
	}
	return binary.BigEndian.AppendUint16(output, uint16(port)), nil
}

func readSocksReply(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != 5 || header[1] != 0 {
		return "", fmt.Errorf("SOCKS5 reply code %d", header[1])
	}
	var host string
	switch header[3] {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 4:
		address := make([]byte, 16)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", err
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = string(address)
	default:
		return "", fmt.Errorf("SOCKS5 invalid address type %d", header[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), nil
}

func socks5Connect(conn net.Conn, target string) error {
	if err := socks5Greeting(conn); err != nil {
		return err
	}
	address, err := socksAddress(target)
	if err != nil {
		return err
	}
	request := append([]byte{5, 1, 0}, address...)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	if _, err := readSocksReply(conn); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}

func runSOCKSUDPSmoke(ctx context.Context, socks, target string, count int) error {
	if count == 0 {
		return nil
	}
	control, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", socks)
	if err != nil {
		return err
	}
	defer control.Close()
	if err := socks5Greeting(control); err != nil {
		return err
	}
	unspecified, _ := socksAddress("0.0.0.0:0")
	if _, err := control.Write(append([]byte{5, 3, 0}, unspecified...)); err != nil {
		return err
	}
	relay, err := readSocksReply(control)
	if err != nil {
		return err
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		return err
	}
	remote, err := net.ResolveUDPAddr("udp4", relay)
	if err != nil {
		return err
	}
	udp, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		return err
	}
	defer udp.Close()
	targetAddress, err := socksAddress(target)
	if err != nil {
		return err
	}
	payload := make([]byte, 1200)
	buffer := make([]byte, len(payload)+300)
	for sequence := 0; sequence < count; sequence++ {
		binary.BigEndian.PutUint32(payload[:4], uint32(sequence))
		fillPattern(payload[4:], int64(sequence)*int64(len(payload)))
		packet := append([]byte{0, 0, 0}, targetAddress...)
		packet = append(packet, payload...)
		_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := udp.Write(packet); err != nil {
			return err
		}
		n, err := udp.Read(buffer)
		if err != nil {
			return fmt.Errorf("datagram %d: %w", sequence, err)
		}
		offset, err := socksUDPHeaderLength(buffer[:n])
		if err != nil {
			return err
		}
		if !bytes.Equal(buffer[offset:n], payload) {
			return fmt.Errorf("datagram %d mismatch", sequence)
		}
	}
	return nil
}

func socksUDPHeaderLength(packet []byte) (int, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return 0, errors.New("invalid SOCKS5 UDP header")
	}
	var addressLength int
	switch packet[3] {
	case 1:
		addressLength = 4
	case 4:
		addressLength = 16
	case 3:
		if len(packet) < 5 {
			return 0, errors.New("truncated SOCKS5 UDP hostname")
		}
		addressLength = 1 + int(packet[4])
	default:
		return 0, fmt.Errorf("invalid SOCKS5 UDP address type %d", packet[3])
	}
	offset := 4 + addressLength + 2
	if len(packet) < offset {
		return 0, errors.New("truncated SOCKS5 UDP packet")
	}
	return offset, nil
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
