package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// ExpandTargets turns the user-supplied target strings (from --targets
// or config.Targets) into a flat list of individual hosts. Each input
// string is one of:
//   - "@path/to/file"  -> read newline-separated hosts from disk
//   - "10.0.0.0/28"    -> expand every usable address in the CIDR block
//   - "example.com" / "10.0.0.5" -> passed through unchanged
//
// CIDR expansion uses net.ParseCIDR + net.IP arithmetic (stdlib only,
// no third-party IP-range libraries). Network and broadcast addresses
// are skipped for IPv4 blocks /31 and larger, matching common scanner
// convention of not bothering to probe non-host addresses.
func ExpandTargets(raw []string) ([]string, error) {
	var out []string
	for _, r := range raw {
		switch {
		case strings.HasPrefix(r, "@"):
			hosts, err := readHostFile(strings.TrimPrefix(r, "@"))
			if err != nil {
				return nil, fmt.Errorf("targets: %w", err)
			}
			out = append(out, hosts...)

		case strings.Contains(r, "/"):
			hosts, err := expandCIDR(r)
			if err != nil {
				return nil, fmt.Errorf("targets: %w", err)
			}
			out = append(out, hosts...)

		default:
			out = append(out, r)
		}
	}
	return out, nil
}

// readHostFile reads one host/CIDR entry per line, skipping blank lines
// and lines beginning with '#' so target lists can be commented.
func readHostFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening host file %s: %w", path, err)
	}
	defer f.Close()

	var hosts []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			expanded, err := expandCIDR(line)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, expanded...)
			continue
		}
		hosts = append(hosts, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading host file %s: %w", path, err)
	}
	return hosts, nil
}

// expandCIDR walks every address in the block using net.IP's built-in
// byte representation, incrementing the last byte(s) manually. This is
// the standard trick for CIDR expansion with only net + stdlib: there's
// no net.CIDRHosts() helper, so we roll our own small increment loop.
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parsing CIDR %s: %w", cidr, err)
	}

	var hosts []string
	// Start from the network address and walk forward until we leave
	// the block (Contains returns false).
	for cur := cloneIP(ip.Mask(ipnet.Mask)); ipnet.Contains(cur); incIP(cur) {
		hosts = append(hosts, cur.String())
	}

	// Skip network (.0) and broadcast (.255) addresses for typical IPv4
	// blocks with more than 2 hosts, since those are never scan targets.
	isIPv4 := ip.To4() != nil
	if isIPv4 && len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// incIP increments an IP address in place, treating it as a big-endian
// byte counter (so 10.0.0.255 -> 10.0.1.0, with carry propagation).
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// LocalSubnet auto-detects the CIDR block of the machine's primary
// non-loopback network interface, using only net.Interfaces() +
// net.Interface.Addrs() — both stdlib, no OS-specific shell-out (no
// parsing `ip addr` or `ifconfig` output). This backs the
// --local-network convenience flag: "scan my LAN" with zero
// configuration, which only works because Go's net package already
// exposes exactly the information ifconfig/ip would otherwise require
// scraping.
//
// Selection rule: the first interface that is UP, not a loopback, and
// has an IPv4 address wins. IPv6-only interfaces are skipped — CIDR
// expansion elsewhere in this package (expandCIDR) is written and
// tested against IPv4 semantics (network/broadcast address skipping in
// particular assumes IPv4-style subnets), so picking an IPv4 interface
// keeps --local-network's output compatible with the rest of the
// pipeline without extra special-casing.
//
// The returned string is in CIDR form (e.g. "192.168.1.42/24") using
// the interface's own address and prefix length — net.ParseCIDR (used
// downstream by expandCIDR) computes the network address from this
// correctly regardless of whether host bits are set, so there's no
// need to zero them out here.
func LocalSubnet() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("local-network: listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue // best-effort: skip interfaces we can't query rather than failing the whole lookup
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			return ipnet.String(), nil
		}
	}

	return "", fmt.Errorf("local-network: no suitable non-loopback IPv4 interface found")
}
