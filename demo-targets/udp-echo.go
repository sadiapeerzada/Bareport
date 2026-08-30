//go:build ignore

package main

import (
	"flag"
	"log"
	"net"
)

// udpEchoServer demonstrates UDP scanning (section 2): it listens on a
// UDP socket and echoes back any datagram it receives, including
// bareport's zero-length probe packet. Because it replies even to an
// empty datagram, a scan against this port should classify as
// StateOpen with high confidence — a useful contrast against a
// genuinely silent UDP port, which can only ever report
// StateOpenFiltered (see scanner/udp.go's documented limitation).
func main() {
	addr := flag.String("addr", ":9999", "listen address")
	flag.Parse()

	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatalf("resolving %s: %v", *addr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listening on %s: %v", *addr, err)
	}
	defer conn.Close()

	log.Printf("udp-echo demo listening on %s", *addr)

	buf := make([]byte, 512)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}
		// Echo back whatever we got (possibly zero bytes) so the
		// sender's socket sees a response and classifies the port
		// as open rather than ambiguous.
		if _, werr := conn.WriteToUDP(buf[:n], raddr); werr != nil {
			log.Printf("write error: %v", werr)
		}
	}
}
