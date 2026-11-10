package csqtt25

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// logCatch keeps what a client logs; for a line that says the workers are
// all ready it also keeps how many WERE ready when the line was written.
type logCatch struct {
	mu      sync.Mutex
	lines   []string
	readyAt []int
	client  atomic.Pointer[Client]
}

const rallyWords = "agreed workers ready"

func (l *logCatch) logf(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	ready := -1
	if strings.Contains(s, rallyWords) {
		// The line can be written a moment before Dial has handed the client
		// to the test.
		for i := 0; i < 200 && l.client.Load() == nil; i++ {
			time.Sleep(5 * time.Millisecond)
		}
		if c := l.client.Load(); c != nil {
			ready = c.Stats().Ready
		}
	}
	l.mu.Lock()
	l.lines = append(l.lines, s)
	if ready >= 0 || strings.Contains(s, rallyWords) {
		l.readyAt = append(l.readyAt, ready)
	}
	l.mu.Unlock()
}

func (l *logCatch) rallies() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, s := range l.lines {
		if strings.Contains(s, rallyWords) {
			out = append(out, s)
		}
	}
	return out
}

func dialLogged(t *testing.T, srv *fakeServer, d *dialer, workers int) (*Client, *logCatch) {
	t.Helper()
	lc := &logCatch{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ClientConfig{Password: srv.password, Workers: workers, Keys: KeysWrap, Dial: d.dial, Logf: lc.logf})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	lc.client.Store(c)
	t.Cleanup(c.Close)
	return c, lc
}

// The client says when every worker the server agreed to is ready, and how
// long that took — after the start, and again after whatever started all of
// them over. Without the line a log has no figure for «how long until the
// tunnel was whole» before the counters a minute later.
func TestTheClientSaysWhenEveryAgreedWorkerIsReady(t *testing.T) {
	took := regexp.MustCompile(`, \d+(\.\d+)?(µs|ms|s) after `)
	check := func(t *testing.T, lc *logCatch, n int, want string, ready int) {
		t.Helper()
		eventually(t, fmt.Sprintf("%d line(s) saying every agreed worker is ready", n), func() bool { return len(lc.rallies()) >= n })
		time.Sleep(200 * time.Millisecond)
		got := lc.rallies()
		if len(got) != n {
			t.Fatalf("the client said %d time(s) that every agreed worker is ready, want %d: %q", len(got), n, got)
		}
		last := got[n-1]
		if !strings.HasPrefix(last, "csqtt25: "+want) || !took.MatchString(last) {
			t.Fatalf("the line reads %q, want it to begin %q and to say how long it took", last, "csqtt25: "+want)
		}
		lc.mu.Lock()
		at := lc.readyAt[n-1]
		lc.mu.Unlock()
		if at != ready {
			t.Fatalf("%d worker(s) were ready when the client said every agreed one was (%q), want %d", at, last, ready)
		}
	}

	t.Run("after the start and after a path change", func(t *testing.T) {
		quickClocks(t)
		srv := newFakeServer(t, "pw-rally-1")
		d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
		c, lc := dialLogged(t, srv, d, 3)
		check(t, lc, 1, "all 3 agreed workers ready", 3)
		if !strings.Contains(lc.rallies()[0], " after the start") {
			t.Fatalf("the first line does not say it counts from the start: %q", lc.rallies()[0])
		}
		// One worker's own restart is not a start of all: nothing is said.
		srv.repair(1, 1, 2)
		eventually(t, "worker 2 dialling again behind a repair", func() bool { return d.count(2) == 2 })
		eventually(t, "three workers ready again", func() bool { return c.Stats().Ready == 3 })
		time.Sleep(100 * time.Millisecond)
		if got := lc.rallies(); len(got) != 1 {
			t.Fatalf("one worker's restart made the client say again that all are ready: %q", got)
		}
		c.OnPathChange()
		check(t, lc, 2, "all 3 agreed workers ready", 3)
		if !strings.Contains(lc.rallies()[1], " after the path change") {
			t.Fatalf("the line behind a path change does not say what it counts from: %q", lc.rallies()[1])
		}
	})

	t.Run("after the server's restart notice", func(t *testing.T) {
		quickClocks(t)
		srv := newFakeServer(t, "pw-rally-2")
		d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
		_, lc := dialLogged(t, srv, d, 2)
		check(t, lc, 1, "all 2 agreed workers ready", 2)
		eventually(t, "the server seeing worker 1 ready", func() bool { return srv.knowsReady(1) })
		srv.say(1, panelRestartNotice)
		check(t, lc, 2, "all 2 agreed workers ready", 2)
		if !strings.Contains(lc.rallies()[1], " after the server's restart notice") {
			t.Fatalf("the line behind a restart notice does not say what it counts from: %q", lc.rallies()[1])
		}
	})

	// The count that matters is the one the server AGREED to, and it can come
	// down after the workers below it are already up: the line is due then.
	t.Run("when the agreed count comes down to the ready ones", func(t *testing.T) {
		quickClocks(t)
		srv := newFakeServer(t, "pw-rally-3")
		srv.set(func() { srv.sayWorkers, srv.denyAbove = false, 2 })
		d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
		release := make(chan struct{})
		var once sync.Once
		let := func() { once.Do(func() { close(release) }) }
		d.setHold(func(id, nth int) <-chan struct{} {
			if id == 3 && nth == 1 {
				return release
			}
			return nil
		})
		c, lc := dialLogged(t, srv, d, 3)
		t.Cleanup(let) // behind Close's: runs before it
		eventually(t, "two workers ready, the third still dialling", func() bool { return c.Stats().Ready == 2 && d.begun(3) == 1 })
		time.Sleep(100 * time.Millisecond)
		if n := len(lc.rallies()); n != 0 {
			t.Fatalf("with two of three asked workers ready the client said every agreed one was: %q", lc.rallies())
		}
		let() // worker 3 asks, is refused for its number, and the count is two
		check(t, lc, 1, "all 2 agreed workers ready", 2)
		if !strings.Contains(lc.rallies()[0], "(3 asked)") {
			t.Fatalf("the line does not say that more were asked for: %q", lc.rallies()[0])
		}
	})
}

// One convention for the engine's log lines: each says whose it is, so that
// whoever prints them — the console, the bridge — adds nothing and a grep for
// the prefix finds all of them.
func TestEveryLogLineOfTheEngineCarriesItsPrefix(t *testing.T) {
	src, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	calls := regexp.MustCompile(`\.Logf\("([^"]*)"`).FindAllStringSubmatch(string(src), -1)
	if len(calls) < 10 {
		t.Fatalf("found %d log calls in client.go, want the engine's ten or more — the scan is looking at the wrong thing", len(calls))
	}
	for _, m := range calls {
		if !strings.HasPrefix(m[1], "csqtt25: ") {
			t.Errorf("a log line without the engine's prefix: %q", m[1])
		}
	}
}
