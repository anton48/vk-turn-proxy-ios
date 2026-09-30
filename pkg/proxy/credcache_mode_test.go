package proxy

// The credential cache is the mode's it was minted in: an anonymous pool's
// file is not loaded by a cookie pool, a cookie pool's not by an anonymous
// one, and a file from before the field is an anonymous one. The console has
// no state of its own to know the mode changed (the app clears the cache from
// Swift): on 2026-09-30 forty connections ran on the previous run's anonymous
// identities in cookie mode. Sabotage seen red: the mode not written; the mode
// not compared at load; a file without a mode taken for the pool's own; the
// mode read from the global flag at save time (the app turns cookie auth off
// at stop, before the pool's last save).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readCacheFile(t *testing.T, path string) credCacheFile {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f credCacheFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTheCacheIsTheModesItWasMintedIn(t *testing.T) {
	logs := captureLog(t)
	SetVKCookieAuth(false, "", nil)
	t.Cleanup(func() { SetVKCookieAuth(false, "", nil) })
	cookieOn := func() { SetVKCookieAuth(true, "remixsid=x", []string{"https://vk.ru/call/join/aaaaaa"}) }
	cookieOff := func() { SetVKCookieAuth(false, "", nil) }
	// Not t.TempDir: every pool's background saver writes its file once more
	// after Close, asynchronously (see the warm-cache test). Each pool below
	// has a file of its own, so no pool's late write can land in another's.
	dir, err := os.MkdirTemp("", "credpool-mode-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	file := func(name string) string { return filepath.Join(dir, name+".json") }
	noMint := func(who string) *fakeMinter {
		return &fakeMinter{fail: func(int) error { return fmt.Errorf("%s must not mint reading its relay", who) }}
	}
	ctx := context.Background()

	// An anonymous pool mints and writes: the file says anon.
	a := NewCredPool(ctx, CredPoolConfig{NumConns: 10, CachePath: file("a"), Fetch: (&fakeMinter{}).fetch})
	if _, _, _, err := a.Acquire(0); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	a.Close()
	if f := readCacheFile(t, file("a")); f.Mode != credCacheModeAnon || len(f.Creds) != 1 {
		t.Fatalf("an anonymous pool wrote mode %q with %d entries, want %q with 1", f.Mode, len(f.Creds), credCacheModeAnon)
	}

	// An anonymous pool reads it: the warm start of the same mode.
	copyFile(t, file("a"), file("b"))
	b := NewCredPool(ctx, CredPoolConfig{NumConns: 10, CachePath: file("b"), Fetch: noMint("an anonymous pool").fetch})
	defer b.Close()
	if hosts := b.RelayHosts(); len(hosts) != 1 {
		t.Fatalf("an anonymous pool did not load the anonymous cache (relays %v)", hosts)
	}

	// A cookie pool does not: the identities stay apart, the file is rewritten
	// as the cookie pool's at its next save.
	copyFile(t, file("a"), file("c"))
	cookieOn()
	c := NewCredPool(ctx, CredPoolConfig{NumConns: 10, CachePath: file("c"), Fetch: noMint("a cookie pool").fetch})
	if hosts := c.RelayHosts(); len(hosts) != 0 {
		t.Fatalf("a cookie pool loaded the anonymous cache (relays %v)", hosts)
	}
	if !strings.Contains(logs(), "the cache holds anon identities and this pool mints cookie — ignoring file") {
		t.Errorf("the anonymous cache was passed over without a line:\n%s", logs())
	}
	c.Close()
	if f := readCacheFile(t, file("c")); f.Mode != credCacheModeCookie || len(f.Creds) != 0 {
		t.Fatalf("after the cookie pool's save the file says mode %q with %d entries, want %q with 0", f.Mode, len(f.Creds), credCacheModeCookie)
	}
	cookieOff()

	// A file from before the field is an anonymous one: loaded by an
	// anonymous pool, passed over by a cookie pool.
	old, err := json.Marshal(credCacheFile{Version: credCacheVersion, SavedAt: time.Now().Unix(), Creds: []credCacheEntry{{
		Slot: 0, Address: "203.0.113.11:19302", Username: fmt.Sprintf("%d:old", time.Now().Add(8*time.Hour).Unix()), Password: "pw",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(old), `"mode"`) {
		t.Fatal("fixture: the old-style file carries a mode")
	}
	for _, name := range []string{"d", "e"} {
		if err := os.WriteFile(file(name), old, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d := NewCredPool(ctx, CredPoolConfig{NumConns: 10, CachePath: file("d"), Fetch: noMint("an anonymous pool").fetch})
	defer d.Close()
	if hosts := d.RelayHosts(); len(hosts) != 1 {
		t.Fatalf("an anonymous pool did not load a cache from before the mode field (relays %v)", hosts)
	}
	cookieOn()
	e := NewCredPool(ctx, CredPoolConfig{NumConns: 10, CachePath: file("e"), Fetch: noMint("a cookie pool").fetch})
	defer e.Close()
	if hosts := e.RelayHosts(); len(hosts) != 0 {
		t.Fatalf("a cookie pool loaded a cache from before the mode field — anonymous identities (relays %v)", hosts)
	}

	// The mode is the pool's from its creation: the app turns cookie auth off
	// at stop, before the pool's last save — the file must still say cookie.
	f := NewCredPool(ctx, CredPoolConfig{NumConns: 10, CachePath: file("f"), Fetch: (&fakeMinter{}).fetch})
	if _, _, _, err := f.Acquire(0); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	cookieOff()
	f.Close()
	if got := readCacheFile(t, file("f")); got.Mode != credCacheModeCookie || len(got.Creds) != 1 {
		t.Fatalf("a cookie pool saved after cookie auth was turned off wrote mode %q with %d entries, want %q with 1", got.Mode, len(got.Creds), credCacheModeCookie)
	}
}
