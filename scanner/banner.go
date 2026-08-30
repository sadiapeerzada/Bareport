package scanner

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
)

// GrabBanner connects to host:port and attempts to read/identify a
// service banner. Most text-based protocols (SSH, FTP, SMTP) announce
// themselves the instant a TCP connection opens, so we read first and
// only send something (a minimal HTTP HEAD request) if nothing arrived
// unprompted — that ordering avoids sending garbage bytes at protocols
// that would misinterpret them.
func GrabBanner(ctx context.Context, host string, port int, timeout time.Duration) (*Banner, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("banner: dialing %s: %w", addr, err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)

	// First, listen for an unsolicited banner (SSH/FTP/SMTP all do this).
	line, err := readLineOrTimeout(reader)
	if err == nil && line != "" {
		return classifyBanner(line), nil
	}

	// Nothing volunteered — try a minimal HTTP HEAD request, since HTTP
	// servers wait for a request before responding.
	req := "HEAD / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, werr := conn.Write([]byte(req)); werr == nil {
		conn.SetReadDeadline(time.Now().Add(timeout))
		line2, err2 := readLineOrTimeout(reader)
		if err2 == nil && line2 != "" {
			return classifyBanner(line2), nil
		}
	}

	// Truly silent or binary: read whatever raw bytes are available (if
	// any arrived at all) and hex-dump them as a last resort.
	raw := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, _ := conn.Read(raw)
	if n > 0 {
		return &Banner{Protocol: "raw", HexDump: hex.EncodeToString(raw[:n])}, nil
	}

	return nil, fmt.Errorf("banner: no data received from %s", addr)
}

// readLineOrTimeout reads a single line (up to \n) or returns an error
// if the deadline fires first / the connection closes with nothing sent.
func readLineOrTimeout(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if line == "" && err != nil {
		return "", err
	}
	return line, nil
}

// classifyBanner inspects the first line of a banner and tags it with
// the protocol it most likely belongs to, based on well-known prefixes
// each protocol's RFC mandates for its greeting line.

// ClassifyBanner is exported specifically for fuzz-testability (see
// tests/banner_fuzz_test.go) — the same reasoning as HasSPFRecord's
// export in scanner/dns.go: this is a pure function processing
// untrusted, attacker-influenced network input (whatever bytes a
// remote service sends back first), which makes it exactly the kind
// of parser worth fuzzing, and it needs no mocking or setup to do so.
func ClassifyBanner(line string) *Banner {
	return classifyBanner(line)
}

func classifyBanner(line string) *Banner {
	switch {
	case strings.HasPrefix(line, "SSH-"):
		return &Banner{Protocol: "ssh", Raw: line}
	case strings.HasPrefix(line, "HTTP/"):
		return &Banner{Protocol: "http", Raw: line}
	case strings.HasPrefix(line, "220") && looksLikeSMTPOrFTP(line):
		// Both SMTP and FTP use a "220 <greeting>" welcome code; a
		// heuristic keyword check disambiguates without a full
		// protocol handshake, since we only grabbed one line.
		if strings.Contains(strings.ToLower(line), "ftp") {
			return &Banner{Protocol: "ftp", Raw: line}
		}
		return &Banner{Protocol: "smtp", Raw: line}
	default:
		if isPrintable(line) {
			return &Banner{Protocol: "unknown-text", Raw: line}
		}
		return &Banner{Protocol: "raw", HexDump: hex.EncodeToString([]byte(line))}
	}
}

func looksLikeSMTPOrFTP(line string) bool {
	return len(line) > 3
}

func isPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && r != '\t' {
			return false
		}
	}
	return true
}
