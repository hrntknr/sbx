package runner

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// Run starts cmd, forwards SIGINT/SIGTERM to it, and waits for it to exit.
// Returns the child's exit code (or 0). A non-nil error means the child could
// not be started. Forwarding (rather than letting the parent die from the
// default signal disposition) lets the caller's deferred cleanup run even
// when sbx receives a non-tty signal such as SIGTERM from a process manager.
func Run(cmd *exec.Cmd) (int, error) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	return run(cmd, sigCh)
}

func run(cmd *exec.Cmd, sigCh <-chan os.Signal) (int, error) {
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig, ok := <-sigCh:
				if !ok {
					return
				}
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 0, err
	}
	return 0, nil
}
