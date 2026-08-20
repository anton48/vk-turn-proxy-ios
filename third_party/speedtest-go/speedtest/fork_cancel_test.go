package speedtest

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Divergence 5 (../FORK.md): a cancelled context must END the phase.
//
// 🚨 THIS TEST GOES THROUGH THE PHASE ENTRY POINTS ON PURPOSE, not through
// TestDirection.Start directly. A direct-Start test is GREEN while the defect is
// live at the call sites: it was measured staying green after
// `request.go:123` was changed back to `.Start(context.Background(), cancel, 0)`,
// which restores the spin on the download phase in production. The signature
// change exists to force all four call sites; only a test that enters where
// production enters can witness that.
//
// The injected request funcs need no network: they are the same seam
// downloadTestContext/uploadTestContext already take.
//
// Seen RED under:
//   - deleting the ctx watcher body in Start (keeping `_ = ctx`)  -> both subtests fail
//   - `.Start(context.Background(), …)` at request.go:123          -> download fails, upload passes
func TestForkCancelEndsThePhaseAtTheCallSites(t *testing.T) {
	const capture = 5 * time.Second
	const budget = 500 * time.Millisecond

	for _, tc := range []struct {
		name string
		run  func(*Server, context.Context, func(context.Context, *Server, int) error) error
	}{
		{"download", func(s *Server, ctx context.Context, f func(context.Context, *Server, int) error) error {
			return s.downloadTestContext(ctx, f)
		}},
		{"upload", func(s *Server, ctx context.Context, f func(context.Context, *Server, int) error) error {
			return s.uploadTestContext(ctx, f)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := New()
			client.SetCaptureTime(capture)
			client.SetNThread(4)
			server := &Server{URL: "http://127.0.0.1:1/speedtest/upload.php", Context: client}

			var calls, afterCancel int64
			var cancelled atomic.Bool
			stub := func(ctx context.Context, _ *Server, _ int) error {
				atomic.AddInt64(&calls, 1)
				if cancelled.Load() {
					atomic.AddInt64(&afterCancel, 1)
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Millisecond):
					return nil
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				time.Sleep(100 * time.Millisecond)
				cancelled.Store(true)
				cancel()
			}()

			start := time.Now()
			if err := tc.run(server, ctx, stub); err != nil {
				t.Fatalf("phase returned %v", err)
			}
			elapsed := time.Since(start)

			if elapsed > 100*time.Millisecond+budget {
				t.Errorf("%s phase ran %v after cancel at 100ms; captureTime is %v — "+
					"Stop does not stop the phase (%d calls, %d of them after cancel)",
					tc.name, elapsed, capture, atomic.LoadInt64(&calls), atomic.LoadInt64(&afterCancel))
			}
		})
	}
}
