package speedtest

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestForkThreadsMeansThreads guards the two changes this fork exists for, and
// it is the regression test for a defect that survived the first one:
//
//   - the adaptive controller is not started, so the worker count does not move
//     once the test is running;
//   - the initial count is NOT clamped to runtime.NumCPU(). Upstream clamped it
//     whenever uploadMaxWorkers <= 8, relying on the controller to grow it back;
//     with the controller gone that clamp is permanent, and `Threads = 8` would
//     run NumCPU workers forever on a phone with fewer cores — while
//     `Threads = 16` ran 16, because the clamp's condition excludes it. A knob
//     that is not monotonic in its own value is worse than a slow one.
//
// The failure this catches is silent: nothing errors, the run simply carries
// fewer flows than the user asked for and the number it prints is attributed to
// the wrong arm.
func TestForkThreadsMeansThreads(t *testing.T) {
	for _, want := range []int{1, 2, 4, 6, 8, 16, 32} {
		dm := NewDataManager()
		dm.SetNThread(want)
		dm.SetCaptureTime(80 * time.Millisecond)

		td := dm.RegisterUploadHandler(func() { time.Sleep(time.Millisecond) })
		ctx, cancel := context.WithCancel(context.Background())
		td.Start(ctx, cancel, 0)

		if got := int(atomic.LoadInt32(&td.activeWorkers)); got != want {
			t.Fatalf("SetNThread(%d): activeWorkers = %d, want %d (NumCPU=%d)",
				want, got, want, runtime.NumCPU())
		}
		if got := int(td.maxWorkers); got != want {
			t.Fatalf("SetNThread(%d): maxWorkers = %d, want %d", want, got, want)
		}
	}
}

// TestForkAdaptiveControllerIsNotStarted fails if a future upstream bump
// silently restores the controller: with it running, a direction whose rate
// collapses loses workers, so activeWorkers stops equalling maxWorkers.
func TestForkAdaptiveControllerIsNotStarted(t *testing.T) {
	dm := NewDataManager()
	dm.SetNThread(8)
	dm.SetCaptureTime(1200 * time.Millisecond) // long enough for >1 controller tick

	td := dm.RegisterUploadHandler(func() { time.Sleep(5 * time.Millisecond) })
	ctx, cancel := context.WithCancel(context.Background())
	td.Start(ctx, cancel, 0)

	if got := int(atomic.LoadInt32(&td.activeWorkers)); got != 8 {
		t.Fatalf("activeWorkers = %d after %v with no confirmed bytes; the adaptive controller appears to be running again",
			got, 1200*time.Millisecond)
	}
}
