package proxy

// Variant A of the post-switch hole (pathrestart.go): the group id rotates
// on a path-up, the restart is debounced behind the last event, and only the
// sessions that announced the OLD id are restarted.

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// A path-up rotates the hello to a new id of the same shape; a disabled
// hello (a third-party peer) stays disabled. Sabotage seen red: the Store
// dropped from rotateGroupHello (the hello does not change).
func TestPathUpRotatesTheGroupHello(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	before := append([]byte(nil), p.groupHelloBytes()...)
	p.rotateGroupHello()
	after := p.groupHelloBytes()
	if bytes.Equal(before, after) {
		t.Fatal("the hello did not change on rotation — the new sessions would join the group the dead ones are in")
	}
	if len(after) != groupHelloLen || !bytes.HasPrefix(after, groupHelloMagic) {
		t.Fatalf("rotated hello has the wrong shape: %x", after)
	}
	var buf bytes.Buffer
	p.sendGroupHello(&buf)
	if !bytes.Equal(buf.Bytes(), after) {
		t.Fatal("sendGroupHello does not send the CURRENT hello")
	}
	third := &Proxy{}
	third.initGroupHello(Config{UseWrapA: true})
	third.rotateGroupHello()
	if third.groupHelloBytes() != nil {
		t.Fatal("a rotation built a hello for a third-party server")
	}
}

// fakeAfter records armed timers and lets the test fire or observe them;
// the returned timer is real but far in the future, so Stop works.
type fakeAfter struct {
	mu    sync.Mutex
	armed []struct {
		d time.Duration
		f func()
		t *time.Timer
	}
}

func (a *fakeAfter) after(d time.Duration, f func()) *time.Timer {
	a.mu.Lock()
	defer a.mu.Unlock()
	t := time.AfterFunc(time.Hour, func() {})
	a.armed = append(a.armed, struct {
		d time.Duration
		f func()
		t *time.Timer
	}{d, f, t})
	return t
}

// The debounce: every path-up bumps the epoch and re-arms ONE timer; when
// it fires, the restart is asked for everything older than the LAST epoch,
// once. Sabotages seen red: the previous timer not stopped (two fires, the
// first with a stale epoch); the epoch not bumped (the second event does
// not move it).
func TestPathRestartDebouncesBehindTheLastEvent(t *testing.T) {
	fa := &fakeAfter{}
	var fired []int64
	r := &pathRestart{after: fa.after, fire: func(e int64) { fired = append(fired, e) }}
	if r.current() != 0 {
		t.Fatalf("epoch before any event: %d", r.current())
	}
	e1 := r.pathUp()
	e2 := r.pathUp() // the second event of one switch, inside the settle
	if e1 != 1 || e2 != 2 || r.current() != 2 {
		t.Fatalf("epochs %d %d current %d — want 1, 2, 2", e1, e2, r.current())
	}
	fa.mu.Lock()
	armed := append([]struct {
		d time.Duration
		f func()
		t *time.Timer
	}(nil), fa.armed...)
	fa.mu.Unlock()
	if len(armed) != 2 || armed[0].d != pathRestartSettle {
		t.Fatalf("armed %d timer(s) at %v, want 2 at %s", len(armed), armed, pathRestartSettle)
	}
	if armed[0].t.Stop() {
		t.Fatal("the first timer was still live after the second path-up — it would restart with epoch 1 and miss the sessions that reconnected on the ghost path")
	}
	armed[1].f()
	if len(fired) != 1 || fired[0] != 2 {
		t.Fatalf("fired %v, want one restart for everything older than epoch 2", fired)
	}
}

// The restart cancels only the sessions that stamped an OLDER epoch —
// one that reconnected on its own after the rotation already announces the
// new group and is spared — and tolerates a conn with no running session.
// Sabotage seen red: the epoch comparison dropped (the new session is
// cancelled too).
func TestRestartSessionsOlderThanSparesTheNewOnes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fa := &fakeAfter{}
	p := &Proxy{ctx: ctx, connEpoch: make([]int64, 3), connCancel: make([]func(), 3)}
	p.pathRestart.after = fa.after // no real timer: the test calls the restart itself
	p.pathRestart.fire = func(int64) {}
	var oldCancelled, newCancelled int
	p.beginConnSession(0, func() { oldCancelled++ }) // epoch 0
	p.pathRestart.pathUp()                           // epoch 1
	p.beginConnSession(1, func() { newCancelled++ }) // epoch 1: reconnected after the rotation
	// conn 2: between sessions, no cancel registered
	p.restartSessionsOlderThan(1, "test")
	if oldCancelled != 1 || newCancelled != 0 {
		t.Fatalf("old cancelled %d, new cancelled %d — want 1 and 0", oldCancelled, newCancelled)
	}
	p.endConnSession(0)
	p.restartSessionsOlderThan(1, "test again")
	if oldCancelled != 1 {
		t.Fatal("a session that already ended was cancelled again")
	}
}

// The tunnel's own start report can reach OnPathUp before any session exists
// (the seeded path: 1.5 s before conn 0; the unseeded path: while conn 0's
// bootstrap handshake is in flight). Before the first established session a
// path-up rotates the hello and arms NO restart — an unseeded bootstrap must
// not lose its attempt to its own start's report. After the first session,
// path-ups restart as before.
//
// Sabotage seen red: the gate dropped from OnPathUp (a restart timer armed and
// the epoch bumped on a proxy that never had a session).
func TestPathUpBeforeTheFirstSessionArmsNoRestart(t *testing.T) {
	p := &Proxy{bootstrapDoneCh: make(chan error, 1)}
	p.initGroupHello(Config{})
	fa := &fakeAfter{}
	p.pathRestart.after = fa.after
	p.pathRestart.fire = func(int64) {}
	armed := func() int {
		fa.mu.Lock()
		defer fa.mu.Unlock()
		return len(fa.armed)
	}

	before := append([]byte(nil), p.groupHelloBytes()...)
	p.OnPathUp()
	if bytes.Equal(before, p.groupHelloBytes()) {
		t.Fatal("the start's path-up did not rotate the hello — the bootstrap must announce a fresh id")
	}
	if n := armed(); n != 0 {
		t.Fatalf("%d restart timer(s) armed before any session existed — the unseeded bootstrap would be cancelled by its own start", n)
	}
	if e := p.pathRestart.current(); e != 0 {
		t.Fatalf("epoch %d before the first session, want 0", e)
	}

	// A FATAL bootstrap signal is not a session: the gate stays shut.
	p.signalBootstrapDone(errors.New("first connection failed"))
	p.OnPathUp()
	if n := armed(); n != 0 {
		t.Fatalf("%d restart timer(s) armed after a fatal bootstrap signal — only a session that carried traffic opens the gate", n)
	}

	p.signalBootstrapDone(nil) // conn 0 carries traffic
	p.OnPathUp()
	if n := armed(); n != 1 {
		t.Fatalf("%d restart timer(s) armed after the first session, want 1", n)
	}
	if e := p.pathRestart.current(); e != 1 {
		t.Fatalf("epoch %d after the first real path-up, want 1", e)
	}
}
