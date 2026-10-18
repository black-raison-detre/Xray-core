package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	host4 := flag.String("host4", "198.51.100.10", "IPv4 address to bind")
	host6 := flag.String("host6", "2001:db8:198:51::10", "IPv6 address to bind")
	flag.Parse()
	errors := make(chan error, 4)
	go func() { errors <- serveTCP("tcp4", net.JoinHostPort(*host4, "18080")) }()
	go func() { errors <- serveUDP("udp4", net.JoinHostPort(*host4, "15353")) }()
	go func() { errors <- serveTCP("tcp6", net.JoinHostPort(*host6, "18080")) }()
	go func() { errors <- serveUDP("udp6", net.JoinHostPort(*host6, "15353")) }()
	if err := <-errors; err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serveTCP(network, address string) error {
	listener, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			buffer := make([]byte, 64*1024)
			for {
				n, err := conn.Read(buffer)
				if err != nil {
					return
				}
				if _, err := conn.Write(buffer[:n]); err != nil {
					return
				}
			}
		}()
	}
}

func serveUDP(network, address string) error {
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return err
	}
	buffer := make([]byte, 64*1024)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if _, err := conn.WriteTo(buffer[:n], peer); err != nil {
			return err
		}
	}
}
