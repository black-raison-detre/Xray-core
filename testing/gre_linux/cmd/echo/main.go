package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	host := flag.String("host", "198.51.100.10", "address to bind")
	flag.Parse()
	errors := make(chan error, 2)
	go func() { errors <- serveTCP(net.JoinHostPort(*host, "18080")) }()
	go func() { errors <- serveUDP(net.JoinHostPort(*host, "15353")) }()
	if err := <-errors; err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serveTCP(address string) error {
	listener, err := net.Listen("tcp4", address)
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

func serveUDP(address string) error {
	conn, err := net.ListenPacket("udp4", address)
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
