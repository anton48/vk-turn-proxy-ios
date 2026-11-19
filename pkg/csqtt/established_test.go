package csqtt

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"
)

// The lease hears that its session is ESTABLISHED — the server answered
// through its relay — once, behind Allocated: the word a pool that marked a
// relay for refusing the server waits for (an accepted allocation is not it:
// the refusing relay accepted the allocation too). A session the server never
// answers says nothing.
func TestTheLeaseHearsThatItsSessionIsEstablished(t *testing.T) {
	leases := func() (func(context.Context, int) (Credential, error), func() map[int][]string) {
		var mu sync.Mutex
		calls := map[int][]string{}
		note := func(id int, what string) {
			mu.Lock()
			calls[id] = append(calls[id], what)
			mu.Unlock()
		}
		creds := func(_ context.Context, id int) (Credential, error) {
			return Credential{
				TURNCredentials: TURNCredentials{Username: "u", Password: "p", Address: "127.0.0.1:19302"},
				Release:         func() {},
				Allocated:       func(time.Time) { note(id, "allocated") },
				Established:     func() { note(id, "established") },
			}, nil
		}
		return creds, func() map[int][]string {
			mu.Lock()
			defer mu.Unlock()
			out := map[int][]string{}
			for id, c := range calls {
				out[id] = append([]string(nil), c...)
			}
			return out
		}
	}
	t.Run("a session that came up", func(t *testing.T) {
		srv := newFakeServer(t)
		loopbackRelay(t, func(TURNCredentials) error { return nil })
		creds, heard := leases()
		c := dialReady(t, testConfig(srv, 2, creds))
		defer c.Close()
		want := map[int][]string{1: {"allocated", "established"}, 2: {"allocated", "established"}}
		if got := heard(); !reflect.DeepEqual(got, want) {
			t.Fatalf("the leases heard %v, want %v", got, want)
		}
	})
	t.Run("a session the server never answers", func(t *testing.T) {
		srv := newFakeServer(t)
		loopbackRelay(t, func(TURNCredentials) error { return nil })
		creds, heard := leases()
		cfg := testConfig(srv, 1, creds)
		cfg.Password = "not-the-servers" // a wrong password is silence
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		if c, err := Dial(ctx, cfg); err == nil {
			c.Close()
			t.Fatal("fixture: a session came up under a wrong password")
		}
		got := heard()
		if len(got[1]) == 0 || got[1][0] != "allocated" {
			t.Fatalf("fixture: the worker's lease heard %v — want an accepted allocation at least", got[1])
		}
		for _, what := range got[1] {
			if what == "established" {
				t.Fatalf("a session the server never answered told its lease it was established: %v", got[1])
			}
		}
	})
}
