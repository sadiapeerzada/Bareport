package scanner

// asOpError/isRefused are pure error-classification helpers with no
// network dependency of their own — they just walk an error's Unwrap()
// chain. tests/scanner_test.go already exercises them indirectly
// through real dials (open/closed/filtered ports), but only along
// whatever specific error shape THIS platform's kernel happens to
// return. Testing directly with synthetic errors lets us cover the
// "wrapped several layers deep", "no OpError anywhere in the chain",
// and "OpError present but the wrapped message doesn't say refused"
// branches deterministically, on any platform.

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestAsOpError_FindsDirectOpError(t *testing.T) {
	target := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	var got *net.OpError
	if ok := asOpError(target, &got); !ok {
		t.Fatal("expected asOpError to find the OpError directly")
	}
	if got != target {
		t.Errorf("expected the exact same *net.OpError back, got a different one")
	}
}

func TestAsOpError_FindsOpErrorSeveralLayersDeep(t *testing.T) {
	inner := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	wrapped := fmt.Errorf("layer one: %w", fmt.Errorf("layer two: %w", inner))

	var got *net.OpError
	if ok := asOpError(wrapped, &got); !ok {
		t.Fatal("expected asOpError to unwrap through multiple fmt.Errorf layers")
	}
	if got != inner {
		t.Error("expected to find the original inner OpError after unwrapping")
	}
}

func TestAsOpError_FalseWhenNoOpErrorAnywhereInChain(t *testing.T) {
	err := fmt.Errorf("outer: %w", errors.New("plain error, never an OpError"))
	var got *net.OpError
	if ok := asOpError(err, &got); ok {
		t.Error("expected asOpError to return false when no OpError is present in the chain")
	}
}

func TestAsOpError_FalseForNilError(t *testing.T) {
	var got *net.OpError
	if ok := asOpError(nil, &got); ok {
		t.Error("expected asOpError(nil, ...) to return false")
	}
}

func TestIsRefused_TrueForConnectionRefusedOpError(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
	if !isRefused(err) {
		t.Error("expected isRefused to be true for an OpError wrapping a 'connection refused' message")
	}
}

func TestIsRefused_FalseForTimeoutOpError(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: errors.New("i/o timeout")}
	if isRefused(err) {
		t.Error("expected isRefused to be false for a timeout-flavored OpError")
	}
}

func TestIsRefused_FalseWhenNotAnOpErrorAtAll(t *testing.T) {
	if isRefused(errors.New("some unrelated error")) {
		t.Error("expected isRefused to be false for a plain, non-OpError error")
	}
}

func TestIsRefused_TrueThroughWrappedOpError(t *testing.T) {
	inner := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	wrapped := fmt.Errorf("dialing host: %w", inner)
	if !isRefused(wrapped) {
		t.Error("expected isRefused to see through a wrapped OpError")
	}
}
