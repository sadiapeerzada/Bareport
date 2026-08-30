package cli

// promptForTarget is unexported but, notably, doesn't touch os.Stdin
// directly — it takes an io.Reader/io.Writer, specifically so this
// kind of direct, real-stdin-free unit test is possible. (Run() is the
// thing that supplies os.Stdin when wiring this up for real
// interactive use; that wiring itself isn't unit-tested, for the same
// reason real OS signal delivery isn't — there's no meaningful way to
// fake "the user's actual terminal" from within `go test`.)

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestPromptForTarget_ReturnsTrimmedInput(t *testing.T) {
	in := strings.NewReader("  192.168.1.1  \n")
	var out bytes.Buffer

	got, err := promptForTarget(in, &out)
	if err != nil {
		t.Fatalf("promptForTarget: %v", err)
	}
	if got != "192.168.1.1" {
		t.Errorf("expected trimmed input %q, got %q", "192.168.1.1", got)
	}
	if !strings.Contains(out.String(), "No target specified") {
		t.Errorf("expected the prompt text to be written to out, got %q", out.String())
	}
}

func TestPromptForTarget_EmptyLineAtEOF(t *testing.T) {
	// bufio.Scanner.Scan() returns false immediately on a reader with
	// zero bytes (clean EOF, no partial line) — the "nothing entered"
	// case this function documents as returning ("", nil).
	in := strings.NewReader("")
	var out bytes.Buffer

	got, err := promptForTarget(in, &out)
	if err != nil {
		t.Fatalf("expected no error for a clean EOF with nothing entered, got: %v", err)
	}
	if got != "" {
		t.Errorf("expected an empty string for EOF-with-nothing-entered, got %q", got)
	}
}

// failingReader always returns a non-EOF error, to exercise
// promptForTarget's sc.Err() branch (distinct from the clean-EOF case
// above, which deliberately returns a nil error).
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.New("simulated read failure")
}

func TestPromptForTarget_ReadError(t *testing.T) {
	var out bytes.Buffer
	_, err := promptForTarget(failingReader{}, &out)
	if err == nil {
		t.Fatal("expected an error when the underlying reader fails")
	}
}

var _ io.Reader = failingReader{}
