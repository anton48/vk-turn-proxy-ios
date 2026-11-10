package csqtt25

import (
	"context"
	"errors"
	"testing"
	"time"
)

// NOCONF — the password is right and the server has no address for it — is
// an answer no retry changes: the client ends with it, at the dial after ONE
// allocation and when it comes to a running client, so that whoever started
// it can say why instead of timing out.
func TestNoConfigEndsTheClientWithItsReason(t *testing.T) {
	t.Run("at the dial", func(t *testing.T) {
		quickClocks(t)
		srv := newFakeServer(t, "pw-noconf-1")
		srv.set(func() { srv.noconf = true })
		d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		t0 := time.Now()
		c, err := Dial(ctx, ClientConfig{Password: srv.password, Workers: 3, Keys: KeysWrap, Dial: d.dial})
		if err == nil {
			c.Close()
			t.Fatal("a client came up on a server that has no address for it")
		}
		if !errors.Is(err, ErrNoConfig) {
			t.Fatalf("the dial ended with %q after %v and %d allocation(s): the server's answer never reached the caller", err, time.Since(t0).Round(time.Millisecond), d.begun(1))
		}
		if n := d.begun(1); n != 1 {
			t.Fatalf("the dial asked %d times before it gave the server's answer up, want once", n)
		}
	})
	t.Run("while running", func(t *testing.T) {
		quickClocks(t)
		srv := newFakeServer(t, "pw-noconf-2")
		c, d, _ := startClient(t, srv, 2, KeysWrap)
		eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
		srv.set(func() { srv.noconf = true })
		srv.repair(1, 1, 2) // worker 2 asks again and is told there is no address
		select {
		case <-c.Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("the client went on after NOCONF: worker 2 asked %d times", d.begun(2))
		}
		if err := c.Err(); !errors.Is(err, ErrNoConfig) {
			t.Fatalf("the client ended with %v, want the server's NOCONF", err)
		}
	})
}

// growBackOff ends worker id's session on the server's word n times, so that
// its next failure waits base << n.
func growBackOff(t *testing.T, c *Client, srv *fakeServer, d *dialer, id, workers, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		before := d.count(id)
		srv.repair(1, uint64(i), id)
		eventually(t, "the worker dialling again behind a repair", func() bool { return d.count(id) == before+1 })
		eventually(t, "every worker ready again", func() bool { return c.Stats().Ready == workers })
	}
}

// lastGap is the time between worker id's last two dials.
func lastGap(d *dialer, id int) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	ts := d.times[id]
	return ts[len(ts)-1].Sub(ts[len(ts)-2])
}

func backOffClocks(t *testing.T) {
	t.Helper()
	oldBase, oldMax, oldHeld := backoffBase, backoffMax, heldAfter
	backoffBase, backoffMax, heldAfter = 100*time.Millisecond, 5*time.Second, 300*time.Millisecond
	t.Cleanup(func() { backoffBase, backoffMax, heldAfter = oldBase, oldMax, oldHeld })
}

// A session that HELD ends the run of failures behind it HOWEVER it ended —
// also when it ended on a path change, which dials again without looking at
// the wait: the failure that follows on the new path waits the base, not
// what the failures of long ago had grown the wait to.
func TestASessionThatHeldEndsTheRunOfFailuresAlsoWhenAPathChangeEndsIt(t *testing.T) {
	quickClocks(t)
	backOffClocks(t)
	srv := newFakeServer(t, "pw-held-path")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	growBackOff(t, c, srv, d, 2, 2, 3) // waits of 100, 200, 400 ms: the next failure would wait 800
	time.Sleep(2 * heldAfter)          // …and then the session holds

	srv.set(func() { srv.dropGetconf[2] = true }) // worker 2's next set-up fails: no configuration
	before := d.count(2)
	c.OnPathChange()
	eventually(t, "worker 2 dialling on the new path, and again behind its failure", func() bool { return d.count(2) == before+2 })
	// The failed set-up itself takes the two configuration waits (300 ms).
	if gap := lastGap(d, 2); gap > 300*time.Millisecond+400*time.Millisecond {
		t.Fatalf("behind a session that had held, the first failure on the new path was followed %v later: it waited what the old failures had grown (800 ms), not the base (%v)",
			gap.Round(10*time.Millisecond), backoffBase)
	}
}

// …and when it ended because the server lowered the count and the worker was
// parked.
func TestASessionThatHeldEndsTheRunOfFailuresAlsoWhenItIsParked(t *testing.T) {
	quickClocks(t)
	backOffClocks(t)
	srv := newFakeServer(t, "pw-held-parked")
	c, d, _ := startClient(t, srv, 3, KeysWrap)
	eventually(t, "three workers ready", func() bool { return c.Stats().Ready == 3 })
	growBackOff(t, c, srv, d, 3, 3, 3)
	time.Sleep(2 * heldAfter)

	srv.set(func() { srv.limit = 2 })
	srv.repair(1, 10, 2) // worker 2 asks again and is told the count is two: worker 3 is parked
	eventually(t, "worker 3 parked", func() bool { st := c.Stats(); return st.Target == 2 && st.Ready == 2 })
	srv.set(func() { srv.limit = 3; srv.dropGetconf[3] = true })
	before := d.count(3)
	srv.repair(1, 11, 2) // …and again, and is told three: worker 3 dials, and its set-up fails
	eventually(t, "worker 3 dialling when the count rose, and again behind its failure", func() bool { return d.count(3) == before+2 })
	if gap := lastGap(d, 3); gap > 300*time.Millisecond+400*time.Millisecond {
		t.Fatalf("behind a session that had held and was parked, the first failure was followed %v later: it waited what the old failures had grown (800 ms), not the base (%v)",
			gap.Round(10*time.Millisecond), backoffBase)
	}
}
