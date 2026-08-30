package tests

// scanner_bench_test.go implements section 18: benchmark scan
// throughput at different worker-pool sizes. Run with:
//
//	go test -bench=. -benchtime=3x .
//
// -benchtime=3x (rather than the default time-based duration) is
// recommended here because each iteration itself scans a fixed, fairly
// large port set — a time-based benchtime would run an unpredictable,
// potentially very large number of full scans instead of a fixed count.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"bareport/scanner"
)

// benchPortRange is how many ports we scan per benchmark iteration: a
// realistic mostly-closed port sweep (one genuinely open port plus a
// large block of closed ones), which exercises the worker pool's
// steady-state throughput rather than a best-case all-open or
// all-closed shape.
const benchPortRange = 500

// benchTimeout keeps dial timeouts short so scanning ~500 mostly-
// closed ports per iteration stays fast on loopback, where refused
// connections return almost instantly anyway — this mainly bounds the
// pathological case.
const benchTimeout = 200 * time.Millisecond

// startBenchServer spins up a plain HTTP server on an ephemeral port
// so each benchmark iteration includes one genuinely "open" result,
// exercising the same dial+read+close path a real scan hits, not just
// refused-connection speed.
func startBenchServer(b *testing.B) (host string, port int, cleanup func()) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})}
	go srv.Serve(ln)

	hostStr, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	fmt.Sscanf(portStr, "%d", &p)
	return hostStr, p, func() { srv.Close() }
}

// runScanBenchmark is shared by every BenchmarkScanTCP_* variant below;
// only the worker count differs, which is exactly the variable section
// 18 asks us to compare throughput across.
func runScanBenchmark(b *testing.B, workers int) {
	host, openPort, cleanup := startBenchServer(b)
	defer cleanup()

	ports := make([]int, 0, benchPortRange)
	for p := openPort; p < openPort+benchPortRange; p++ {
		ports = append(ports, p)
	}

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results := scanner.ScanTCP(ctx, []string{host}, ports, workers, benchTimeout)
		if len(results) != len(ports) {
			b.Fatalf("expected %d results, got %d", len(ports), len(results))
		}
	}
}

func BenchmarkScanTCP_Workers10(b *testing.B)  { runScanBenchmark(b, 10) }
func BenchmarkScanTCP_Workers50(b *testing.B)  { runScanBenchmark(b, 50) }
func BenchmarkScanTCP_Workers100(b *testing.B) { runScanBenchmark(b, 100) }
func BenchmarkScanTCP_Workers500(b *testing.B) { runScanBenchmark(b, 500) }
