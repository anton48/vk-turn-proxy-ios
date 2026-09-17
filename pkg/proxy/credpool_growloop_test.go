package proxy

import (
	"context"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// goFuncBody returns the source of the top-level function whose signature
// starts with sig — from the signature to its closing brace at column 0 — with
// line comments cut. The window is the construct itself: a fixed length reads
// the neighbour. (The cut is a plain "//" split; none of the scanned bodies
// holds a "//" inside a string.)
func goFuncBody(t *testing.T, file, sig string) string {
	t.Helper()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, sig)
	if i < 0 {
		t.Fatalf("%s: %q not found", file, sig)
	}
	j := strings.Index(s[i:], "\n}\n")
	if j < 0 {
		t.Fatalf("%s: %q has no closing brace at column 0", file, sig)
	}
	var b strings.Builder
	for _, ln := range strings.Split(s[i:i+j+3], "\n") {
		if k := strings.Index(ln, "//"); k >= 0 {
			ln = ln[:k]
		}
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return b.String()
}

// The grower's state machine exists ONCE. Both owners of a credPool — Proxy
// (native) and CredPool (csqtt) — wait for their own readiness and then run
// credPool.growLoop; neither keeps a loop, a cold-start target or a fill of
// its own: a second copy gets every fix second and its tests never (only Grow
// was ever driven by a test). Native runs at the production pace — the numbers
// live in defaultGrowPace alone — with the captcha-pending predicate; csqtt
// has no captcha UI and passes nil. Inside the loop the target is the pool's
// own number (the one get()'s cap uses) and the hold is a tick's first step.
// Sabotages seen red: native passing nil for the predicate; native with a
// pace of its own; Grow keeping a loop of its own; growLoop computing its own
// target; the hold moved after the slot pick.
func TestBothGrowersRunTheOneLoop(t *testing.T) {
	native := goFuncBody(t, "proxy.go", "func (p *Proxy) growCredPool(")
	if !strings.Contains(native, "p.WaitBootstrap(defaultGrowPace.bootstrap)") {
		t.Error("Proxy.growCredPool does not take its bootstrap wait from defaultGrowPace")
	}
	if !strings.Contains(native, "p.credPool.growLoop(ctx, defaultGrowPace, p.captchaPending)") {
		t.Error("Proxy.growCredPool does not run credPool.growLoop at the production pace with the captcha-pending predicate")
	}
	standalone := goFuncBody(t, "credpool.go", "func (p *CredPool) Grow(")
	if !strings.Contains(standalone, "p.cp.growLoop(ctx, p.pace, nil)") {
		t.Error("CredPool.Grow does not run credPool.growLoop at the pool's pace with no predicate")
	}
	ownLoop := regexp.MustCompile(`(?m)^\s*for\b`)
	for name, body := range map[string]string{"Proxy.growCredPool": native, "CredPool.Grow": standalone} {
		if ownLoop.MatchString(body) {
			t.Errorf("%s keeps a loop of its own — the state machine lives in credPool.growLoop alone", name)
		}
		for _, own := range []string{"tryFill(", "pickSlotToFill(", "coldStartTargetValue(", "snapshotSize("} {
			if strings.Contains(body, own) {
				t.Errorf("%s calls %s itself — the state machine lives in credPool.growLoop alone", name, strings.TrimSuffix(own, "("))
			}
		}
	}

	loop := goFuncBody(t, "credpool.go", "func (cp *credPool) growLoop(")
	if !strings.Contains(loop, "coldStartSlots := cp.coldStartTargetValue()") {
		t.Error("growLoop computes its own cold-start target instead of reading the pool's")
	}
	hold, pick := strings.Index(loop, "hold != nil && hold()"), strings.Index(loop, "cp.pickSlotToFill()")
	if hold < 0 || pick < 0 || hold > pick {
		t.Errorf("growLoop must consult hold before it picks a slot (hold at %d, pick at %d)", hold, pick)
	}
}

// While a captcha is waiting for the user the grower adds no VK pressure: a
// held tick mints nothing and the next one comes a SLOW interval later; once
// the captcha is gone the fill resumes and reaches the cold-start target. The
// predicate is a parameter, so this runs on a bare pool in milliseconds.
// Sabotages seen red: growLoop ignoring hold (a mint while held); a held tick
// re-armed at the fast interval (the polls come pace.fast apart).
func TestGrowLoopHoldsWhileACaptchaIsPending(t *testing.T) {
	m := &fakeMinter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 12, 2*time.Minute, "", m.fetch)
	cp.setColdStartTarget(30) // target = 3 slots of 12
	pace := growPace{fast: 2 * time.Millisecond, slow: 25 * time.Millisecond, staggerMin: 150 * time.Millisecond, staggerMax: 200 * time.Millisecond}

	var held atomic.Bool
	held.Store(true)
	var mu sync.Mutex
	var heldPolls []time.Time
	hold := func() bool {
		h := held.Load()
		if h {
			mu.Lock()
			heldPolls = append(heldPolls, time.Now())
			mu.Unlock()
		}
		return h
	}
	polls := func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), heldPolls...)
	}
	done := make(chan struct{})
	go func() { cp.growLoop(ctx, pace, hold); close(done) }()

	// Four held polls — or a mint, which ends the wait at once and fails below.
	deadline := time.After(3 * time.Second)
	for len(polls()) < 4 && m.count() == 0 {
		select {
		case <-deadline:
			t.Fatalf("the held grower polled %d times in 3 s — it must keep polling, at the slow interval", len(polls()))
		case <-time.After(time.Millisecond):
		}
	}
	if c := m.count(); c != 0 {
		t.Fatalf("%d mint(s) while a captcha was pending — a held tick must not fetch", c)
	}
	// A timer never fires early, so the gaps can only be LONGER than slow under
	// load; shorter means the held tick was re-armed at another interval.
	at := polls()
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < pace.slow-3*time.Millisecond {
			t.Fatalf("held polls %d→%d are %s apart — a held tick must wait the slow interval (%s)", i-1, i, gap, pace.slow)
		}
	}

	held.Store(false)
	deadline = time.After(3 * time.Second)
	for {
		if available, _, _ := cp.snapshotSize(); available >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("the fill did not resume once the captcha was gone: %d mints", m.count())
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("growLoop did not return when its context ended")
	}
}

// captchaPending is the native grower's predicate: true exactly while a
// captcha URL is stored. Sabotage seen red: always false.
func TestCaptchaPendingReadsTheStoredURL(t *testing.T) {
	p := &Proxy{}
	if p.captchaPending() {
		t.Fatal("pending with nothing ever stored")
	}
	p.captchaImageURL.Store("https://id.vk.ru/not_robot_captcha?sid=1")
	if !p.captchaPending() {
		t.Fatal("not pending with a captcha URL stored")
	}
	p.captchaImageURL.Store("")
	if p.captchaPending() {
		t.Fatal("still pending after the URL was cleared")
	}
}
