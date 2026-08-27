package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	source := flag.String("source", "192.168.50.100", "source address")
	target := flag.String("target", "198.51.100.10", "echo-server address")
	flag.Parse()
	family, tcpNetwork, udpNetwork, err := addressFamily(*source, *target)
	if err != nil {
		fail(err)
	}
	if err := testTCP(tcpNetwork, *source, *target); err != nil {
		fail(err)
	}
	for _, size := range []int{32, 4096} {
		if err := testUDP(udpNetwork, *source, *target, size); err != nil {
			fail(err)
		}
	}
	fmt.Printf("GRE_NAMESPACE_TRAFFIC_OK family=%s tcp=1 udp=2 fragmented_udp=1\n", family)
}

func addressFamily(source, target string) (string, string, string, error) {
	sourceIP, targetIP := net.ParseIP(source), net.ParseIP(target)
	if sourceIP == nil || targetIP == nil {
		return "", "", "", fmt.Errorf("invalid source or target address")
	}
	if sourceIP.To4() != nil && targetIP.To4() != nil {
		return "ipv4", "tcp4", "udp4", nil
	}
	if sourceIP.To4() == nil && targetIP.To4() == nil {
		return "ipv6", "tcp6", "udp6", nil
	}
	return "", "", "", fmt.Errorf("source and target address families differ")
}

func testTCP(network, source, target string) error {
	payload := []byte("xray-gre-tcp")
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}, Timeout: 5 * time.Second}
	conn, err := dialer.Dial(network, net.JoinHostPort(target, "18080"))
	if err != nil {
		return fmt.Errorf("TCP dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("TCP write: %w", err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("TCP read: %w", err)
	}
	if !bytes.Equal(reply, payload) {
		return fmt.Errorf("TCP echo mismatch")
	}
	return nil
}

func testUDP(network, source, target string, size int) error {
	payload := bytes.Repeat([]byte{byte(size)}, size)
	conn, err := net.DialUDP(network, &net.UDPAddr{IP: net.ParseIP(source)}, &net.UDPAddr{IP: net.ParseIP(target), Port: 15353})
	if err != nil {
		return fmt.Errorf("UDP %d dial: %w", size, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("UDP %d write: %w", size, err)
	}
	reply := make([]byte, len(payload))
	n, err := conn.Read(reply)
	if err != nil {
		return fmt.Errorf("UDP %d read: %w", size, err)
	}
	if n != len(payload) || !bytes.Equal(reply[:n], payload) {
		return fmt.Errorf("UDP %d echo mismatch: bytes=%d", size, n)
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
