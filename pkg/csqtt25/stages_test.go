package csqtt25

import (
	"context"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// stagedConn is a dialled socket that says what its dial was made of.
type stagedConn struct {
	net.PacketConn
	stages []Stage
}

func (s stagedConn) DialStages() []Stage { return s.stages }

func dialStaged(t *testing.T, srv *fakeServer, workers int, dial DialFunc) (*Client, *logCatch) {
	t.Helper()
	lc := &logCatch{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ClientConfig{Password: srv.password, Workers: workers, Keys: KeysWrap, Dial: dial, Logf: lc.logf})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	lc.client.Store(c)
	t.Cleanup(c.Close)
	return c, lc
}

var stageDur = `[0-9.]+(?:µs|ms|s)`

func durOf(t *testing.T, s string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("not a duration: %q", s)
	}
	return d
}

// The «all ready» line names the stream that was ready LAST — the one that set
// the figure — and what its set-up took: the dial's own stretches as its conn
// says them (in their order, word for word), then the keys, then the
// configuration.
func TestTheAllReadyLineSaysWhatTheLastStreamsSetUpTook(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-stages-1")
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
	said := []Stage{{"lease", 510 * time.Millisecond}, {"allocation", 2900 * time.Millisecond}, {"permission", 120 * time.Millisecond}}
	_, lc := dialStaged(t, srv, 3, func(ctx context.Context, id int) (net.PacketConn, net.Addr, func(), error) {
		if id == 3 {
			time.Sleep(250 * time.Millisecond) // worker 3 is ready last
		}
		conn, peer, closer, err := d.dial(ctx, id)
		if err != nil {
			return nil, nil, nil, err
		}
		if id == 3 {
			return stagedConn{conn, said}, peer, closer, nil
		}
		return conn, peer, closer, nil
	})
	eventually(t, "the all-ready line", func() bool { return len(lc.rallies()) == 1 })
	line := lc.rallies()[0]
	want := regexp.MustCompile(`after the start — the last one, worker 3: began \+` + stageDur + `, lease 510ms, allocation 2\.9s, permission 120ms, keys ` + stageDur + `, configuration ` + stageDur + `$`)
	if !want.MatchString(line) {
		t.Fatalf("the line does not say what the last stream's set-up took: %q", line)
	}
}

// A conn that says nothing of its dial has the dial as ONE stretch, measured —
// and what the line lists adds up to the figure it explains: the last stream's
// start behind the moment all were started, plus its stretches.
func TestADialThatSaysNothingIsOneStretchAndTheStretchesAddUpToTheFigure(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-stages-2")
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
	_, lc := dialStaged(t, srv, 2, func(ctx context.Context, id int) (net.PacketConn, net.Addr, func(), error) {
		if id == 2 {
			time.Sleep(150 * time.Millisecond)
		}
		return d.dial(ctx, id)
	})
	eventually(t, "the all-ready line", func() bool { return len(lc.rallies()) == 1 })
	line := lc.rallies()[0]
	m := regexp.MustCompile(`ready, (` + stageDur + `) after the start — the last one, worker 2: began \+(` + stageDur + `), dial (` + stageDur + `), keys (` + stageDur + `), configuration (` + stageDur + `)$`).FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("the line does not carry the plain dial's stretches: %q", line)
	}
	took, began, dial, keys, conf := durOf(t, m[1]), durOf(t, m[2]), durOf(t, m[3]), durOf(t, m[4]), durOf(t, m[5])
	if dial < 150*time.Millisecond || dial > 2*time.Second {
		t.Fatalf("the dial took 150 ms and more, the line says %v: %q", dial, line)
	}
	sum := began + dial + keys + conf
	if sum > took+5*time.Millisecond || sum < took-500*time.Millisecond {
		t.Fatalf("the stretches add up to %v, the figure is %v: %q", sum, took, line)
	}
}

// After whatever started all the workers over the line speaks of the NEW
// sessions: the last one's start is counted from that moment.
func TestTheStretchesAreTheNewSessionsBehindAPathChange(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-stages-3")
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
	c, lc := dialStaged(t, srv, 2, d.dial)
	eventually(t, "the first all-ready line", func() bool { return len(lc.rallies()) == 1 })
	time.Sleep(300 * time.Millisecond) // the first sessions' set-ups lie well before the path change
	c.OnPathChange()
	eventually(t, "the second all-ready line", func() bool { return len(lc.rallies()) == 2 })
	line := lc.rallies()[1]
	m := regexp.MustCompile(`ready, (` + stageDur + `) after the path change — the last one, worker [12]: began \+(` + stageDur + `), dial `).FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("the line behind a path change does not speak of a stream's set-up: %q", line)
	}
	if took, began := durOf(t, m[1]), durOf(t, m[2]); began > took {
		t.Fatalf("the last stream began %v behind the path change and all were ready %v behind it: %q", began, took, line)
	}
}

// The tail's own rules: nothing without a stream, nothing for a stream that was
// ready before all were started over (it took no part), a start before that
// moment reads +0s, every stretch to the millisecond in its order.
func TestTheLineTailNamesOnlyAStreamThatTookPart(t *testing.T) {
	since := time.Unix(1700000000, 0)
	var none *streamSetup
	if got := none.words(1, since); got != "" {
		t.Fatalf("no stream said %q", got)
	}
	old := &streamSetup{began: since.Add(-3 * time.Second), ready: since.Add(-time.Second), stages: []Stage{{"dial", time.Second}}}
	if got := old.words(1, since); got != "" {
		t.Fatalf("a stream ready before the start of all said %q", got)
	}
	s := &streamSetup{began: since.Add(-40 * time.Millisecond), ready: since.Add(time.Second),
		stages: []Stage{{"lease", 510400 * time.Microsecond}, {"allocation", 2900 * time.Millisecond}, {"handshake", 600 * time.Microsecond}}}
	if got, want := s.words(7, since), " — the last one, worker 7: began +0s, lease 510ms, allocation 2.9s, handshake 1ms"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	s.began = since.Add(80400 * time.Microsecond) // to the millisecond, as the stretches are
	if got := s.words(7, since); !strings.Contains(got, "began +80ms, ") {
		t.Fatalf("a start 80.4 ms behind the moment reads %q", got)
	}
}

// What the dial's part is made of, and the keys' name.
func TestTheDialsPartIsTheConnsWordOrTheWholeDial(t *testing.T) {
	said := []Stage{{"allocation", time.Second}}
	got := dialStages(stagedConn{stages: said}, 5*time.Second)
	if len(got) != 1 || got[0] != said[0] {
		t.Fatalf("a stager's word was not taken: %v", got)
	}
	got[0].Name = "changed"
	if said[0].Name != "allocation" {
		t.Fatal("the session's list is the conn's own slice")
	}
	if got := dialStages(stagedConn{}, 5*time.Second); len(got) != 1 || got[0] != (Stage{"dial", 5 * time.Second}) {
		t.Fatalf("a stager with nothing to say is not the whole dial: %v", got)
	}
	if got := dialStages(nil, 70*time.Millisecond); len(got) != 1 || got[0] != (Stage{"dial", 70 * time.Millisecond}) {
		t.Fatalf("a plain conn is not the whole dial: %v", got)
	}
	if keysStage(KeysWrap) != "keys" || keysStage(KeysAuto) != "handshake" || keysStage(KeysDTLS) != "handshake" {
		t.Fatalf("the keys' stretch is named %q / %q / %q", keysStage(KeysWrap), keysStage(KeysAuto), keysStage(KeysDTLS))
	}
}
