//go:build ignore

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

// tcpEchoServer demonstrates banner grabbing on a non-HTTP port
// (section 4): on connect, it immediately sends an SSH-looking banner
// line (without implementing any real SSH protocol beyond that one
// line), then echoes back whatever the client sends — enough for
// bareport's banner grabber to classify it via the "SSH-" prefix rule
// in scanner/banner.go without needing a real SSH server.
func main() {
	addr := flag.String("addr", ":2222", "listen address")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listening on %s: %v", *addr, err)
	}
	log.Printf("tcp-echo demo (fake SSH banner) listening on %s", *addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleEchoConn(conn)
	}
}

func handleEchoConn(conn net.Conn) {
	defer conn.Close()

	fmt.Fprintf(conn, "SSH-2.0-bareport_demo_1.0\r\n")

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			if _, werr := conn.Write([]byte(line)); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("read error: %v", err)
			}
			return
		}
	}
}
