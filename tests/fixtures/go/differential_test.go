// Differential tests: the vulnerable functions must actually misbehave where their VULN comments
// say they do, and their clean counterparts must not.
//
// validate.py's anchors prove a planted construct was not deleted. They cannot prove it still
// *does* anything -- a fix that leaves the anchored text in place and neutralises it elsewhere
// slips past. These tests close that residue for the rows whose defect is observable in-process.
//
// GO-07 is deliberately not exercised here: a concurrent map write is an unrecoverable Go runtime
// fatal error, not a panic, so recover() cannot catch it and triggering it would take the whole
// test binary down rather than failing one case. TestGO07 runs it in a subprocess instead.
package fixture

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GO-01: the vulnerable version dereferences a nil *Config after logging the error; the clean one
// returns the error instead.
func TestGO01NilDerefAfterLoggedError(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("EffectiveLimit should panic on malformed JSON -- GO-01 no longer fires")
		}
	}()
	EffectiveLimit([]byte("{not json"))
}

func TestGO01CleanReturnsError(t *testing.T) {
	if _, err := EffectiveLimitSafe([]byte("{not json")); err == nil {
		t.Fatal("EffectiveLimitSafe should return an error, not panic or succeed")
	}
}

// GO-02: a one-value assertion panics on an unexpected shape; the two-value form reports !ok.
func TestGO02AssertionPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("TenantName should panic on a non-map claim -- GO-02 no longer fires")
		}
	}()
	TenantName("not a map")
}

func TestGO02CleanReportsNotOK(t *testing.T) {
	if _, ok := TenantNameSafe("not a map"); ok {
		t.Fatal("TenantNameSafe should report !ok on a non-map claim")
	}
}

// GO-06 has no vulnerable-side check here, and cannot have a useful one. DecodeEvent returns only
// an Event, so "error discarded" and "error logged then a zero Event returned" are indistinguishable
// to any caller -- a test asserting the zero value passes against a correct fix. That is not a gap
// worth papering over with an assertion that cannot fail; validate.py's ANCHOR on the `_ =` discard
// is what holds this row, and tests/README.md lists it in the anchors-only column.
//
// The clean side is checkable, because returning the error is the whole difference.
func TestGO06CleanSurfacesDecodeError(t *testing.T) {
	if _, err := DecodeEventSafe([]byte("{not json")); err == nil {
		t.Fatal("DecodeEventSafe should surface the decode error the vulnerable one swallows")
	}
}

// GO-05: defer runs at function exit, not iteration exit, so descriptors pile up for the whole
// loop. Counting descriptors *around* the call cannot see that -- by the time TotalSize returns,
// its defers have run and the count is back to baseline either way. An earlier version of this
// test did exactly that and passed against a correct fix, which is no test at all.
//
// The observable consequence is descriptor exhaustion, so that is what this exercises: a child
// process with a low RLIMIT_NOFILE walks more files than it has descriptors for. Holding them all
// open makes os.Open start failing partway through, and the silently-continuing loop undercounts.
// Closing per iteration completes accurately.
func TestGO05DefersExhaustDescriptors(t *testing.T) {
	const fileCount = 200
	const fdLimit = 64

	if os.Getenv("FIXTURE_GO05_CHILD") == "1" {
		var lim syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
			fmt.Println("SETRLIMIT-UNAVAILABLE")
			os.Exit(0)
		}
		lim.Cur = fdLimit
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
			fmt.Println("SETRLIMIT-UNAVAILABLE")
			os.Exit(0)
		}

		dir, err := os.MkdirTemp("", "go05")
		if err != nil {
			fmt.Println("SETRLIMIT-UNAVAILABLE")
			os.Exit(0)
		}
		defer os.RemoveAll(dir)

		paths := make([]string, 0, fileCount)
		for i := 0; i < fileCount; i++ {
			p := fmt.Sprintf("%s/f%03d", dir, i)
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				fmt.Println("SETRLIMIT-UNAVAILABLE")
				os.Exit(0)
			}
			paths = append(paths, p)
		}

		fmt.Printf("VULNERABLE-TOTAL=%d\n", TotalSize(paths))
		safe, err := TotalSizeSafe(paths)
		fmt.Printf("CLEAN-TOTAL=%d CLEAN-ERR=%v\n", safe, err)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestGO05DefersExhaustDescriptors", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "FIXTURE_GO05_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	text := string(out)
	if strings.Contains(text, "SETRLIMIT-UNAVAILABLE") {
		t.Skip("cannot lower RLIMIT_NOFILE on this platform")
	}

	if !strings.Contains(text, fmt.Sprintf("CLEAN-TOTAL=%d", fileCount)) {
		t.Fatalf("TotalSizeSafe should count every file under a tight fd limit:\n%s", text)
	}
	if strings.Contains(text, fmt.Sprintf("VULNERABLE-TOTAL=%d", fileCount)) {
		t.Fatalf("TotalSize counted all %d files under a %d-descriptor limit, so it is no longer "+
			"holding them open across the loop -- GO-05 no longer fires:\n%s",
			fileCount, fdLimit, text)
	}
}

// GO-07: concurrent map write is fatal, so it can only be observed from outside the process.
// Re-runs this same binary with a marker env var set, and asserts the child dies saying so.
func TestGO07ConcurrentMapWriteIsFatal(t *testing.T) {
	if os.Getenv("FIXTURE_GO07_CHILD") == "1" {
		for i := 0; i < 1000; i++ {
			RecordHit("k")
		}
		// Bounded, not select{}: if the map write has been made safe the child must exit cleanly
		// and quickly, so the parent's assertion fails in seconds rather than at the test timeout.
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestGO07ConcurrentMapWriteIsFatal", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "FIXTURE_GO07_CHILD=1")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatal("child exited cleanly -- GO-07's unsynchronised map write no longer races")
	}
	if !strings.Contains(string(out), "concurrent map writes") &&
		!strings.Contains(string(out), "fatal error") {
		t.Fatalf("child died, but not from the planted race:\n%s", out)
	}
}

// GO-07 clean counterpart: the mutex-guarded counter survives the same hammering.
func TestGO07CleanCounterIsSafe(t *testing.T) {
	c := NewHitCounter()
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				c.Record("k")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
	if got := c.Count("k"); got != 5000 {
		t.Fatalf("HitCounter lost writes under contention: got %d, want 5000", got)
	}
}
