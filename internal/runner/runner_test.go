package runner

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestRunForwardsSignalToChild(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	sigCh := make(chan os.Signal, 1)

	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := run(cmd, sigCh)
		done <- result{code, err}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for cmd.Process == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cmd.Process == nil {
		t.Fatal("child did not start")
	}

	sigCh <- syscall.SIGTERM

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("unexpected error: %v", r.err)
		}
		if r.code == 0 {
			t.Errorf("expected non-zero exit code from killed sleep, got 0")
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("run did not return after forwarded SIGTERM")
	}
}
