// Package speedtest wraps showwin/speedtest-go for the iOS app's in-app speed
// test. It runs in the APP, never in the network extension: a many-flow load
// generator next to the extension's ~50 MB jetsam budget is what builds 130-146
// were about.
//
// Design notes that are not obvious from the code:
//
//   - ONE RUN PER PROCESS. The guard lives here, at package scope, not in a view
//     model: a guard scoped to one object cannot protect a process-wide resource,
//     which is exactly how build 271 ended up with two concurrent load runs.
//     🚨 Servers() takes the SAME guard. Fetching the list is not a lookup — the
//     engine pings every server in it concurrently for up to 4 s — so doing it
//     during a run is a second generator inside the measurement.
//
//   - POLLED, NOT CALLBACK-DRIVEN. Progress crosses into Swift by polling a
//     snapshot rather than by a cgo callback. The app already polls stats, and it
//     keeps the C surface to four plain functions.
//
//   - TWO RESULTS, ALWAYS. The library reports a blended estimator
//     (0.5*EWMA + 0.5*mean of the last 5 s) whose value depends on how long the
//     phase actually ran; we also compute raw = confirmed bytes over the window
//     they were measured in. Only the raw figure is comparable across runs.
//
//   - EARLY STOP IS A PER-RUN CHOICE, not a fixed property of the engine.
//     Upstream ends a phase once the rate is stable (CV < 3%), so Duration is a
//     CEILING and a requested 15 s lands at ~10 s. Fork divergence 3 added
//     SetEarlyStop, and research mode turns it off to hold a fixed window; plan()
//     is the single place that decides. The ACTUAL per-phase duration is measured
//     and reported either way.
//
//   - THREADS MEANS TCP CONNECTIONS, and only because this package forces it.
//     The engine's own transport sets ForceAttemptHTTP2, and the measured URL is
//     https after resolveUploadURL follows the endpoint's 307 — so N workers
//     multiplexed onto ONE connection and every thread-count comparison measured
//     nothing. This package supplies its own transport with HTTP/2 disabled and
//     COUNTS the connections, so the claim is checked at run time rather than
//     assumed. Numbers collected before 2026-08-20 were taken under that defect.
package speedtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	stgo "github.com/showwin/speedtest-go/speedtest"
)

// forkRevision is the number of deliberate divergences in
// third_party/speedtest-go (see its FORK.md). It is part of EngineVersion
// because those divergences CHANGE THE METHODOLOGY — the thread count means
// something different, phases end at a different time — so "speedtest-go
// v1.7.11" alone does not identify what produced a number.
//
// 🚨 It cannot drift: TestEngineVersionNamesEveryForkDivergence reads FORK.md,
// counts its "## Divergence N:" sections and fails if they disagree. Together
// with the fork's own TestForkDivergesFromUpstreamExactlyHere — which fails on a
// divergence nobody documented — the loop closes in both directions:
// undocumented change -> that guard; documented but unnamed here -> this one.
const forkRevision = 5

// methodRevision is how THIS package measures — see METHOD.md.
//
// 🚨 THE FORK REVISION ALONE WAS NOT ENOUGH, and four builds proved it. Builds
// 315-318 all reported the same version because the fork did not move, while the
// wrapper changed what "8 threads" means, what the connection count counts, and
// whether a phase was primed at all. Their results cannot go in one series and
// the label said they could.
//
// Bump it when a change alters what a number MEANS — the load offered, the
// window it is averaged over, the connections it runs on, or the conditions
// under which a figure is published. Not for wording, UI or tests.
// TestEngineVersionNamesEveryMethodRevision fails if this and METHOD.md
// disagree.
const methodRevision = 6

// EngineVersion is reported beside every result so a number can be traced to the
// code that produced it. The upstream version is READ FROM THE LIBRARY rather
// than typed here, so a bump cannot leave the label behind.
//
// On the upstream version itself: v1.7.10 counted ATTEMPTED upload bytes (added
// as the transport read the request body, before the server confirmed); 1.7.11
// splits that into a separate read-volume accumulator. Do not go back.
//
// ⚠️ It still does not identify the BINARY — two builds can share all three
// numbers. The app puts its own build number beside this on screen, which is the
// only thing that pins the exact code.
var EngineVersion = fmt.Sprintf("speedtest-go v%s+fork.%d / vkturn-method.%d",
	stgo.Version(), forkRevision, methodRevision)

// Limits on what the C surface will accept. wgSpeedtestStart takes arbitrary
// JSON, so these are enforced here rather than trusted from the caller: Swift
// constrains all three today, and "today" is not a guarantee.
const (
	maxThreads  = 32
	minDuration = 5
	maxDuration = 120
)

// Config is what the UI collects. JSON tags match the Swift side.
type Config struct {
	ServerID    string `json:"server_id"` // "" = automatic selection
	Threads     int    `json:"threads"`   // 1..32
	Direction   string `json:"direction"` // "download" | "upload" | "both"
	DurationSec int    `json:"duration_sec"`
	Research    bool   `json:"research"` // warm-up discarded, raw metric preferred
	Debug       bool   `json:"debug"`    // engine debug logging (worker counts, URLs)
}

// ServerInfo is one row of the picker.
type ServerInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Sponsor string `json:"sponsor"`
	Country string `json:"country"`
	Host    string `json:"host"`

	// Distance is OOKLA'S ESTIMATE, computed from where Ookla believes this
	// device is — which can be wrong by a continent. Measured 2026-08-20: a user
	// in Funchal was placed at [40.851, -8.399] on the mainland, so their own
	// city's server was reported 1186 km away and servers 249 km from nobody
	// were listed as nearest.
	Distance float64 `json:"distance_km"`

	// LatencyMs is MEASURED — the list fetch pings every server it returns — so
	// it is the honest answer to "which of these is actually near me" wherever
	// the distance is not. Zero means the ping did not come back.
	LatencyMs float64 `json:"latency_ms"`
}

// Phase carries one direction's outcome. Library and Raw are both kept on
// purpose: they answer different questions and disagreeing is normal.
type Phase struct {
	LibraryMbps float64 `json:"library_mbps"` // the blended EWMA5 estimator
	RawMbps     float64 `json:"raw_mbps"`     // confirmed bytes * 8 / actual elapsed
	Bytes       int64   `json:"bytes"`
	ActualSec   float64 `json:"actual_sec"`

	// ImpliedSec is the duration the reported rate and the reported byte count
	// IMPLY. Consistent is false when it disagrees with the measured window by
	// more than 25%.
	//
	// This exists because the tool's own CLI has been seen to print rows that
	// cannot both be true: 958.23 MB at 228.86 Mbit/s implies 33.5 s inside a
	// window capped at 15 s (2026-08-20, server 31551). Three runs through this
	// API on the same server did NOT reproduce it, and the cause is unknown — so
	// rather than trust or distrust the engine wholesale, every result carries
	// the check. A number whose own bytes disagree with its own rate must never
	// be shown as a plain figure.
	// WarmupSec and WindowSec split ActualSec, and they are MEASURED, not the
	// values that were requested: WarmupSec is how long the discarded prefix
	// actually lasted and WindowSec is the window RawMbps covers. Outside
	// research mode WarmupSec is 0 and WindowSec == ActualSec.
	//
	// 🚨 THE UI MUST NOT SUBTRACT. It used to print ActualSec beside a RawMbps
	// computed over a shorter window, so a research run read "20.0s" next to a
	// rate measured over 15 — two numbers on one line that could not both be
	// true. A quantity derived in two places is this project's recurring defect,
	// so the split is computed once, here, and shipped.
	WarmupSec float64 `json:"warmup_sec"`
	WindowSec float64 `json:"window_sec"`

	// WindowBytes is what RawMbps was computed from. Bytes is the WHOLE phase,
	// warm-up included.
	//
	// 🚨 IN RESEARCH MODE THOSE ARE DIFFERENT NUMBERS, and without this field a
	// reader checking `Bytes / WindowSec` against RawMbps gets a mismatch and
	// concludes the tool is lying — the arithmetic that is supposed to VERIFY a
	// line instead condemns a correct one. Shipping both is what keeps a result
	// self-checkable in either mode.
	WindowBytes int64   `json:"window_bytes"`
	ImpliedSec  float64 `json:"implied_sec"`
	Consistent  bool    `json:"consistent"`

	// ConnsUsed is how many distinct TCP connections CARRIED THIS PHASE'S DATA;
	// Dials is how many were newly opened for it.
	//
	// 🚨 Used, not open. Counting open connections reads as healthy on a pool
	// full of sockets the measurement never touched — measured: 7 idle sockets
	// from server discovery plus 1 multiplexed HTTP/2 socket gave "8 of 8" and
	// no warning. Under HTTP/2 the used count is 1 however many workers run,
	// which is precisely the state every thread-count comparison was silently
	// taken in until 2026-08-20.
	ConnsUsed int `json:"conns_used"`
	Dials     int `json:"dials"`

	// UPLOAD ONLY. Confirmed bytes are counted after the server's response, so
	// the two below say whether the bytes we pushed were actually ACCEPTED.
	//
	// This is the signal that would have caught the Frankfurt endpoint in one
	// glance: that host answers a POST with 307, nothing is ever confirmed, and
	// a ratio of 0.0 says so — where the old engine simply reported a speed.
	// Backlog is bytes read out of our body but not yet confirmed; a backlog
	// that keeps growing means requests are going out and not coming back.
	BacklogBytes   int64   `json:"backlog_bytes"`
	ConfirmedRatio float64 `json:"confirmed_ratio"`

	// BacklogTailBytes is how much of the backlog a NORMAL end of phase
	// explains: every worker has one chunk in flight when the phase stops, and
	// those bytes are pushed and never confirmed through no fault of the
	// server. Printed beside the backlog so the number qualifies itself
	// instead of reading as refusal — see confirmRatio.
	BacklogTailBytes int64 `json:"backlog_tail_bytes"`

	// Warnings is what the UI shows instead of a bare number when the figure
	// cannot be trusted. Empty means nothing was detected — not that the number
	// is right.
	Warnings []string `json:"warnings,omitempty"`
}

// Progress is the whole snapshot Swift polls.
type Progress struct {
	State     string `json:"state"` // idle | servers | running | done | error
	Stage     string `json:"stage"` // ping | download | upload
	Err       string `json:"error,omitempty"`
	ServerID  string `json:"server_id"`
	ServerStr string `json:"server_desc"`
	ServerURL string `json:"server_url"`

	// What OOKLA believes this device's address is — NOT necessarily its address.
	// Measured 2026-08-20: four independent services (ipify, ifconfig.me,
	// icanhazip, checkip.amazonaws) all reported 176.78.47.118 while Ookla's own
	// speedtest-config.php reported 85.246.4.193. The library faithfully repeats
	// what that endpoint says, so the discrepancy is Ookla's, not the library's.
	//
	// ⇒ label it "as seen by Ookla" in any UI. That framing is not a hedge: this
	// value is precisely what drives SERVER SELECTION, so it is the right thing
	// to show when explaining why the list looks the way it does — and with the
	// tunnel up it reflects the EXIT rather than the user, which is the honest
	// way to see whether a run went through the VPN. It is simply not an
	// identity claim.
	OoklaSeesIP  string  `json:"ookla_sees_ip"`
	OoklaSeesISP string  `json:"ookla_sees_isp"`
	PingMs       float64 `json:"ping_ms"`
	Threads      int     `json:"threads"`
	Requested    int     `json:"requested_sec"`

	// Direction and Mode describe the run that produced this snapshot, so a
	// result can be rendered without consulting whatever the UI's controls
	// happen to say NOW. Mode is authored by plan(), the function that actually
	// calls SetEarlyStop, so the label cannot disagree with the setting.
	Direction string `json:"direction"`
	Mode      string `json:"mode"`

	// 🚨 POINTERS, AND OMITTED WHEN THE DIRECTION DID NOT RUN. As values these
	// were always marshalled, so a download-only run emitted a complete, tidy
	// upload object of zeros — indistinguishable on the wire from a measured
	// 0.0 Mbit/s. Any consumer that renders what it is given reproduced the
	// fabrication; making it absent is the only fix that survives the next
	// consumer.
	Down      *Phase `json:"download,omitempty"`
	Up        *Phase `json:"upload,omitempty"`
	Engine    string `json:"engine"`
	Estimator string `json:"estimator"`
}

// activity is what this package is doing, as ONE value.
//
// 🚨 IT REPLACED A BOOL, AND THE BOOL WAS NOT A GUARD. `running` was set only by
// Start, and Servers merely READ it and let the lock go — so a fetch could begin
// in the instant before a run claimed the flag, a run could start while a fetch
// was already in flight, and nothing at all stopped two fetches. Reading a flag
// is not taking a guard; only a state transition under one lock is.
//
// This matters because a server-list fetch is a LOAD GENERATOR: the engine pings
// every server in the list concurrently. The founding rule of this package is
// that two generators would measure each other.
type activity int

const (
	idle activity = iota
	loadingServers
	runningTest
)

func (a activity) String() string {
	switch a {
	case loadingServers:
		return "loading the server list"
	case runningTest:
		return "running a speed test"
	}
	return "idle"
}

var (
	mu     sync.Mutex
	state  activity
	cancel context.CancelFunc
	snap   Progress
)

// claim moves idle -> want atomically, or refuses and says what is in the way.
func claim(want activity) error {
	mu.Lock()
	defer mu.Unlock()
	if state != idle {
		return fmt.Errorf("busy: %s — %s would measure it", state, want)
	}
	state = want
	return nil
}

func release() {
	mu.Lock()
	state = idle
	mu.Unlock()
}

func setSnap(f func(*Progress)) {
	mu.Lock()
	f(&snap)
	mu.Unlock()
}

// Snapshot returns the current progress. Safe to call at any cadence.
func Snapshot() Progress {
	mu.Lock()
	defer mu.Unlock()
	return snap
}

// Cancel stops a run in progress. Idempotent.
func Cancel() {
	mu.Lock()
	c := cancel
	mu.Unlock()
	if c != nil {
		c()
	}
}

// serverListTimeout bounds the whole list fetch. There was no bound at all: the
// bridge passed context.Background(), the client has no Timeout and the
// transport sets no ResponseHeaderTimeout, so a peer that accepted the
// connection and never answered hung the fetch for the life of the process —
// while the UI's "loading" latch, which hides its own retry button, never
// cleared. Killing the app was the only way out.
const serverListTimeout = 20 * time.Second

// Servers fetches the selectable list. NOTE: the list is built from this
// device's APPARENT IP, so with the tunnel up it describes servers near the
// EXIT and with it down servers near the user. The caller must say which,
// because the same "auto" otherwise measures two different paths silently.
func Servers(ctx context.Context) ([]ServerInfo, error) {
	// 🚨 THIS TAKES THE GUARD, it does not consult it. Fetching the list is not
	// a lookup: the engine pings EVERY server in it concurrently, under its own
	// detached 4 s deadline, before returning. Doing that during a measurement
	// puts a second load generator inside it, and the picker is reachable
	// mid-run — one tap away.
	if err := claim(loadingServers); err != nil {
		return nil, err
	}
	defer release()

	ctx, cancel := context.WithTimeout(ctx, serverListTimeout)
	defer cancel()

	client := newEngine(1, false)
	// A list fetch opens a connection to every server it pings. None of them is
	// wanted afterwards.
	defer client.close()
	if _, err := client.FetchUserInfoContext(ctx); err != nil {
		return nil, fmt.Errorf("fetch user info: %w", err)
	}
	list, err := client.FetchServerListContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch server list: %w", err)
	}
	return describe(list), nil
}

// FindServers asks OOKLA rather than filtering the list we already hold.
//
// 🚨 THE LOCAL FILTER CANNOT REACH WHAT THE LIST DOES NOT CONTAIN, and that is
// not a corner case. The nearby list is built from the apparent IP, so a user in
// Funchal whom Ookla places on the mainland never sees the server in their own
// city — the one with sub-millisecond latency — however they spell it in the
// search box. `search=` is a query parameter on Ookla's own endpoint and finds
// it; filtering rows we already have never can.
//
// A query of digits is looked up BY ID, because a user who knows the id should
// not have to guess how its sponsor is spelled — and because the run path has
// always accepted an arbitrary id, so the picker was the only thing standing
// between them and it.
func FindServers(ctx context.Context, query string) ([]ServerInfo, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("nothing to search for")
	}
	// 🚨 A keyword search performs the SAME fan-out ping as a plain list fetch,
	// so it takes the same guard. It is a load generator, not a lookup.
	if err := claim(loadingServers); err != nil {
		return nil, err
	}
	defer release()

	ctx, cancel := context.WithTimeout(ctx, serverListTimeout)
	defer cancel()

	if isServerID(query) {
		client := newEngine(1, false)
		defer client.close()
		server, err := client.FetchServerByIDContext(ctx, query)
		if problem := idLookupError(query, server, err); problem != nil {
			return nil, problem
		}
		return describe(stgo.Servers{server}), nil
	}

	client := newEngineWithKeyword(query)
	defer client.close()
	if _, err := client.FetchUserInfoContext(ctx); err != nil {
		return nil, fmt.Errorf("fetch user info: %w", err)
	}
	list, err := client.FetchServerListContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("search %q: %w", query, err)
	}
	return describe(list), nil
}

// idLookupError decides what a lookup's outcome MEANS, and it is a separate
// function so the rule can be tested without a network.
//
// 🚨 "THERE IS NO SERVER WITH ID X" IS A CLAIM ABOUT OOKLA'S DATABASE, and only
// one outcome supports it. Collapsing every failure into it told a user with a
// perfectly good id that their server does not exist — and the reasonable
// reaction to that is to stop trying the id, which is the one thing they should
// keep doing. A timeout, a decode failure and a cancelled context say nothing
// about whether the server exists.
func idLookupError(query string, server *stgo.Server, err error) error {
	switch {
	case errors.Is(err, stgo.ErrServerNotFound):
		return fmt.Errorf("no server with id %s", query)
	case err != nil:
		return fmt.Errorf("looking up server %s: %w", query, err)
	case server == nil:
		// No error and no server: the library should not do this, but reporting
		// success with a nil server would crash describe().
		return fmt.Errorf("no server with id %s", query)
	}
	return nil
}

func isServerID(q string) bool {
	for _, r := range q {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// describe turns the library's servers into what the picker shows, in one place
// so the nearby list and a search cannot describe the same server differently.
func describe(list stgo.Servers) []ServerInfo {
	out := make([]ServerInfo, 0, len(list))
	for _, s := range list {
		info := ServerInfo{
			ID:       s.ID,
			Name:     s.Name,
			Sponsor:  s.Sponsor,
			Country:  s.Country,
			Host:     s.Host,
			Distance: s.Distance,
		}
		// PingTimeout is the library's sentinel for "no answer", and it is a
		// huge duration — reporting it as a latency would put an unreachable
		// server at the bottom of a sort by a number that looks measured.
		if s.Latency > 0 && s.Latency < time.Second {
			info.LatencyMs = float64(s.Latency.Microseconds()) / 1000
		}
		out = append(out, info)
	}
	return out
}

// runPlan is everything the engine is configured with, decided in ONE place.
//
// It exists because the three settings are entangled: research mode needs the
// capture time EXTENDED to cover a warm-up it then discards, AND early stop
// turned off, or the "fixed window" it promises is neither fixed nor a window.
// Deciding them at three call sites is how the previous version ended up
// discarding a warm-up without extending the capture whenever duration_sec was
// 0 — unreachable from the UI, reachable through the bridge's JSON.
type runPlan struct {
	threads   int
	direction string
	requested time.Duration
	capture   time.Duration
	warmup    time.Duration
	earlyStop bool

	// mode is the label shown beside the result. It is authored HERE, by the
	// function that actually calls SetEarlyStop, so it cannot claim a
	// methodology the run did not use.
	mode string
}

// plan validates the config and derives the engine settings from it.
func plan(cfg Config) (runPlan, error) {
	p := runPlan{threads: cfg.Threads, direction: cfg.Direction}

	if p.threads < 1 {
		p.threads = 1
	}
	if p.threads > maxThreads {
		return runPlan{}, fmt.Errorf("threads %d is above the %d this app will run", cfg.Threads, maxThreads)
	}
	switch p.direction {
	case "":
		p.direction = "both"
	case "download", "upload", "both":
	default:
		// Silently accepting it made BOTH directions false, so run() returned
		// success having measured nothing and the snapshot carried two
		// fabricated zero phases.
		return runPlan{}, fmt.Errorf("direction %q is not one of download, upload, both", cfg.Direction)
	}

	sec := cfg.DurationSec
	if sec == 0 {
		sec = 15
	}
	if sec < minDuration || sec > maxDuration {
		return runPlan{}, fmt.Errorf("duration %ds is outside %d-%ds", cfg.DurationSec, minDuration, maxDuration)
	}
	p.requested = time.Duration(sec) * time.Second

	if cfg.Research {
		p.warmup = researchWarmup
		p.capture = p.requested + p.warmup
		p.earlyStop = false
		p.mode = fmt.Sprintf("research · %.0fs warm-up discarded · fixed %.0fs window",
			p.warmup.Seconds(), p.requested.Seconds())
	} else {
		p.capture = p.requested
		p.earlyStop = true
		p.mode = "standard · early stop on, so the duration is a ceiling"
	}
	return p, nil
}

// Start begins a run. It refuses if one is already in flight — the refusal is
// the point: two concurrent generators would measure each other.
func Start(cfg Config) error {
	// Validate BEFORE taking the guard, so a rejected config does not leave the
	// package marked busy.
	pl, err := plan(cfg)
	if err != nil {
		return err
	}

	if err := claim(runningTest); err != nil {
		return err
	}
	mu.Lock()
	ctx, c := context.WithCancel(context.Background())
	cancel = c
	snap = Progress{
		State:     "running",
		Stage:     "ping",
		Threads:   pl.threads,
		Requested: int(pl.requested.Seconds()),
		Direction: pl.direction,
		Mode:      pl.mode,
		Engine:    EngineVersion,
		Estimator: "EWMA5",
		ServerID:  cfg.ServerID,
	}
	mu.Unlock()

	go func() {
		defer func() {
			mu.Lock()
			cancel = nil
			mu.Unlock()
			release()
		}()
		if err := run(ctx, cfg, pl); err != nil {
			setSnap(func(p *Progress) {
				p.State = "error"
				p.Err = err.Error()
			})
			return
		}
		setSnap(func(p *Progress) { p.State = "done" })
	}()
	return nil
}

// phaseSpec is one direction, so the two phases cannot drift apart by being
// written twice.
type phaseSpec struct {
	stage string
	// sample returns the confirmed-byte counter and the outstanding backlog, so
	// the warm-up boundary can be taken for BOTH and every figure on a result
	// describes the same window.
	sample func() (bytes, backlog int64)
	run    func(context.Context) error
	speed  func() float64
	upload bool
}

func run(ctx context.Context, cfg Config, pl runPlan) error {
	// 🚨 TWO ENGINES, AND THE SEPARATION IS A CORRECTNESS REQUIREMENT.
	//
	// Discovery is not a lookup: FetchUserInfo, the server list and the list's
	// fan-out ping open connections to a dozen hosts and leave them idle in the
	// transport's pool. Sharing one transport with the measurement put those
	// sockets inside the phase's connection accounting — measured as 7 control
	// sockets plus 1 multiplexed HTTP/2 socket reading "8 of 8 threads", a false
	// negative in the one guard that exists to catch h2.
	//
	// So discovery picks the endpoint and is then DONE. The measurement gets a
	// transport of its own, whose pool holds nothing but connections to the
	// target, primed by exactly one ping.
	discovery := newEngine(1, cfg.Debug)
	// Discovery's pool is dead weight the moment the endpoint is chosen, and it
	// is the larger of the two: one connection per server in the list.
	defer discovery.close()

	user, err := discovery.FetchUserInfoContext(ctx)
	if err != nil {
		return fmt.Errorf("fetch user info: %w", err)
	}
	setSnap(func(p *Progress) {
		p.OoklaSeesIP = user.IP
		p.OoklaSeesISP = user.Isp
	})
	list, err := discovery.FetchServerListContext(ctx)
	if err != nil {
		return fmt.Errorf("fetch server list: %w", err)
	}
	var target *stgo.Server
	if cfg.ServerID == "" {
		targets, err := list.FindServer(nil)
		if err != nil || len(targets) == 0 {
			return fmt.Errorf("no server available for automatic selection")
		}
		target = targets[0]
	} else {
		// A pinned id is NOT necessarily in the fetched list: FetchServerList
		// returns servers near this device's APPARENT location, so pinning a
		// distant one — which is the normal case, since the point is to pin the
		// same server across tunnel states — misses. Ask for it by id instead,
		// and only fall back to scanning the list.
		target, err = discovery.FetchServerByIDContext(ctx, cfg.ServerID)
		if err != nil || target == nil {
			for _, s := range list {
				if s.ID == cfg.ServerID {
					target = s
					break
				}
			}
		}
		if target == nil {
			return fmt.Errorf("server %s not found (by id or in the nearby list)", cfg.ServerID)
		}
	}
	// Resolve the redirect BEFORE measuring; see resolveUploadURL.
	if resolved := resolveUploadURL(ctx, target.URL); resolved != target.URL {
		target.URL = resolved
	}
	setSnap(func(p *Progress) {
		p.ServerID = target.ID
		p.ServerStr = fmt.Sprintf("%s · %s", target.Sponsor, target.Name)
		p.ServerURL = target.URL
	})

	// Hand the server over to a FRESH transport, so everything counted from here
	// is the measurement and nothing else. target.Context is the *Speedtest that
	// every measured request goes through, so this switch is what redirects them.
	meas := newEngine(pl.threads, cfg.Debug)
	// Up to MaxIdleConnsPerHost sockets would otherwise sit for the full 90 s
	// idle timeout after the run — several quick runs in a row would hold
	// hundreds at once, on a phone.
	defer meas.close()
	target.Context = meas.Speedtest

	meas.SetCaptureTime(pl.capture)
	meas.SetEarlyStop(pl.earlyStop)
	meas.SetNThread(pl.threads)

	setSnap(func(p *Progress) { p.Stage = "ping" })
	// This ping is also the PRIMING request, and it is load-bearing for the
	// connection count: with an empty pool Go dials once per concurrent request
	// even under HTTP/2 — the thundering herd — so a phase measured from cold
	// reads N connections whatever the protocol. One reusable connection must
	// exist before the workers start, or the guard cannot fail.
	if err := target.PingTestContext(ctx, nil); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	setSnap(func(p *Progress) { p.PingMs = float64(target.Latency.Milliseconds()) })

	specs := map[string]phaseSpec{
		"download": {
			stage:  "download",
			sample: func() (int64, int64) { return target.Context.GetTotalDownload(), 0 },
			run:    target.DownloadTestContext,
			speed:  func() float64 { return float64(target.DLSpeed) },
		},
		"upload": {
			stage: "upload",
			sample: func() (int64, int64) {
				return target.Context.GetTotalUpload(), target.Context.GetUploadBacklog()
			},
			run:    target.UploadTestContext,
			speed:  func() float64 { return float64(target.ULSpeed) },
			upload: true,
		},
	}
	order := []string{"download", "upload"}
	if pl.direction != "both" {
		order = []string{pl.direction}
	}

	for _, name := range order {
		spec := specs[name]
		setSnap(func(p *Progress) { p.Stage = spec.stage })

		// 🚨 PRIME BEFORE RESETTING, EVERY PHASE. The download phase used to be
		// primed only incidentally, by the ping above; the upload phase started
		// from a pool the download had torn down, and an unprimed phase cannot
		// detect HTTP/2 at all — see engine.prime. Seen on the first device run:
		// download reported "8 carried data · 7 opened" (7 dials plus the primed
		// connection, exactly as designed) while upload reported 8 and 8, which
		// is what h2 would have printed too.
		warm := meas.prime(ctx, target.URL)

		// 🚨 NOTHING MAY DIAL BETWEEN reset() AND stats(): anything that does is
		// counted into this phase's connection figures.
		meas.conns.reset()
		start := time.Now()
		ws, err := runPhase(ctx, pl.warmup, spec.sample, spec.run)
		end := time.Now()
		used, dials := meas.conns.stats()
		endBytes, endBacklog := spec.sample()

		// The gate comes AFTER the samples are taken and BEFORE anything is
		// published: a stopped run is not a result. Without it the engine
		// reports success unconditionally — DownloadTestContext returns nil even
		// when the phase was cut short — so Stop produced a fabricated "done".
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		phase := measure(spec.speed(), endBytes, start, end, spec.upload)
		phase = applyWindow(phase, ws, start, end, endBytes, endBacklog, spec.upload, pl.threads)
		// After the gate on purpose: a cancelled phase has peak < threads and
		// would otherwise emit a spurious "the knob lied" warning on every Stop.
		phase = applyConnStats(phase, used, dials, pl.threads, warm)

		done := phase
		setSnap(func(p *Progress) {
			if spec.upload {
				p.Up = &done
			} else {
				p.Down = &done
			}
		})
	}
	return nil
}

// resolveUploadURL follows the endpoint's redirect ONCE, by hand, before any
// measurement starts.
//
// Why this exists: the server list hands out an `http://…:8080/speedtest/…`
// URL, and at least Clouvider's answers a POST with **307 Temporary Redirect**
// to an `https://server-NNNNN.prod.hosts.ooklaserver.net` host. Go's client
// cannot follow that: the request body is a stream with no GetBody, so it is not
// replayable, and the transport stops after ~130 KB of a 1 MB chunk.
//
// The consequence is worse than a failed test. v1.7.10 counted upload bytes as
// the transport READ them and never looked at the status, so it reported a speed
// built on truncated, redirected requests. v1.7.11 checks the status and refuses
// to count them — which is correct, and is why upload reads N/A there until the
// URL is resolved. Resolving it once makes both versions measure accepted bytes.
//
// It uses the same no-HTTP/2 transport as the measurement. This probe reads only
// the status and Location, so h2 here would harm nothing today — but a probe on
// a different transport than the thing it configures is a trap waiting for the
// first person who measures with it.
func resolveUploadURL(ctx context.Context, raw string) string {
	// Its own transport, and it is CLOSED afterwards: one probe leaves one
	// connection idle for the transport's full 90 s timeout otherwise. The two
	// measurement pools are released at the end of a run; this one was the
	// straggler, and a straggler is exactly the kind of thing that survives a
	// cleanup because it is only ever one.
	rt := newRoundTripper(nil)
	defer closeIdle(rt)
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: rt,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // we want to SEE the 307, not chase it
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, strings.NewReader("probe"))
	if err != nil {
		return raw
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return raw
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			if u, err := url.Parse(loc); err == nil && u.Scheme != "" {
				return loc
			}
		}
	}
	return raw
}

// researchWarmup is discarded before the measurement window opens. Five seconds
// is chosen against this tunnel, not from folklore: inner RTT under the VPN runs
// 150-170 ms, so a flow needs several seconds to leave slow start, and the
// engine's own estimator carries a 5 s window.
const researchWarmup = 5 * time.Second

// minRateWindow is the shortest interval a rate may be computed over. A window
// of a few milliseconds turns a handful of bytes into millions of Mbit/s, which
// is not a wrong number so much as a meaningless one presented as a right one.
const minRateWindow = 1.0

// warmSample is what the warm-up goroutine observed, carried back over a channel
// rather than through shared variables.
type warmSample struct {
	warmup  time.Duration // what was REQUESTED, for the message when ok is false
	bytes   int64         // confirmed-byte counter at the boundary
	backlog int64         // unconfirmed bytes outstanding at the boundary
	at      time.Time     // when the boundary was crossed
	ok      bool          // false: the phase ended before the warm-up did
}

// runPhase executes one direction and, when a warm-up is asked for, samples the
// byte counter at the boundary so the raw figure covers the measurement window
// alone.
//
// 🚨 THE CHANNEL IS THE SYNCHRONISATION, AND THE RECEIVE MUST BLOCK. The
// previous version wrote the sample into the enclosing function's named return
// values from the goroutine and merely closed a `done` channel — a signal, not a
// happens-before edge. `go test -race` reported both fields. A non-blocking
// receive (select with default) is no better in a different way: it compiles,
// passes, and silently LOSES the sample when the goroutine has not sent yet,
// which reads as a run with no warm-up.
func runPhase(ctx context.Context, warmup time.Duration, sample func() (bytes, backlog int64), run func(context.Context) error) (warmSample, error) {
	if warmup <= 0 {
		return warmSample{}, phaseErr(ctx, run(ctx))
	}
	ch := make(chan warmSample, 1)
	done := make(chan struct{})
	go func() {
		s := warmSample{warmup: warmup}
		select {
		case <-time.After(warmup):
			s.bytes, s.backlog = sample()
			s.at, s.ok = time.Now(), true
		case <-done:
		case <-ctx.Done():
		}
		ch <- s // exactly one send, on every path
	}()
	err := run(ctx)
	close(done)
	s := <-ch // blocking: this is what orders the goroutine's writes before our reads
	return s, phaseErr(ctx, err)
}

// phaseErr turns a cancelled phase into an error.
//
// The engine reports success unconditionally — DownloadTestContext and
// UploadTestContext both `return nil` even when the phase was cut short — so
// ctx.Err() is the only signal that the numbers about to be measured cover a
// window the user stopped.
func phaseErr(ctx context.Context, err error) error {
	if err == nil {
		return ctx.Err()
	}
	return err
}

// applyWindow splits the phase into the discarded warm-up and the measured
// window, and is the ONLY place RawMbps is decided.
//
// Both halves are MEASURED, not requested, and both are anchored on the same two
// wrapper timestamps as ActualSec — so WarmupSec + WindowSec == ActualSec
// exactly, and the UI can print all three without deriving any of them a second
// time.
func applyWindow(p Phase, s warmSample, start, end time.Time, endBytes, endBacklog int64, upload bool, threads int) Phase {
	if !s.ok {
		p.WindowSec = p.ActualSec
		p.WindowBytes = p.Bytes
		p.BacklogBytes = endBacklog
		if s.warmup > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"the phase ended before the %.0fs warm-up did, so no measurement window opened — "+
					"this figure covers the whole phase, warm-up included", s.warmup.Seconds()))
		}
		return confirmRatio(setRaw(p, p.Bytes, p.WindowSec), upload, threads)
	}
	p.WarmupSec = s.at.Sub(start).Seconds()
	p.WindowSec = end.Sub(s.at).Seconds()
	p.WindowBytes = endBytes - s.bytes
	// 🚨 THE BACKLOG IS SCOPED TO THE WINDOW TOO, and that is not pedantry: the
	// confirmation ratio exists to qualify the RATE, and the rate covers the
	// window. A phase-scoped ratio qualifies a number that appears nowhere —
	// and printed beside window figures it made a correct line fail its own
	// arithmetic (measured on a research run: 98.0% reported, 97.5% implied by
	// the window bytes beside it).
	//
	// It is a DELTA of an outstanding level, so it can be negative when the
	// server caught up during the window; clamped, because a negative backlog is
	// not a thing to report.
	p.BacklogBytes = endBacklog - s.backlog
	if p.BacklogBytes < 0 {
		p.BacklogBytes = 0
	}
	return confirmRatio(setRaw(p, p.WindowBytes, p.WindowSec), upload, threads)
}

// confirmRatio derives the confirmation ratio from the window's own figures, so
// it can never disagree with the bytes printed next to it.
// uploadChunkBytes is the size of ONE upload chunk, and therefore how much a
// single worker can have in flight when the phase ends.
//
// It is not a guess: the measurement loop posts `uploadRequest(ctx, s, 4)`
// (third_party/speedtest-go/speedtest/request.go:151) and the size table there
// is `ulSizes[4] = 1000` kB, giving `(1000*100-51)*10` bytes.
const uploadChunkBytes = (1000*100 - 51) * 10 // 999 490 B

func confirmRatio(p Phase, upload bool, threads int) Phase {
	// 🚨 DOWNLOAD HAS NOTHING TO CONFIRM. A GET's bytes are counted as they
	// ARRIVE, so there is no pushed-but-unaccepted quantity at all — yet this
	// ran for both directions and published `confirmed=100.0%` on every
	// download line (16 of them in 20.08/vpn.wifi.6.log). A ratio that is 1.0
	// by construction reads as "the server accepted everything" when what it
	// means is "this field does not apply", and the struct comment above has
	// said UPLOAD ONLY the whole time.
	if !upload {
		p.BacklogBytes = 0
		p.ConfirmedRatio = 0
		return p
	}

	pushed := p.WindowBytes + p.BacklogBytes
	if pushed > 0 && p.WindowBytes >= 0 {
		p.ConfirmedRatio = float64(p.WindowBytes) / float64(pushed)
	}

	// 🚨 A NORMAL END OF PHASE LOOKS EXACTLY LIKE REFUSED BYTES. When the
	// capture time expires every worker is mid-chunk; those requests are
	// cancelled, their bytes were read out of our body and will never be
	// confirmed, and they land in the backlog. The tail is therefore
	// threads × one chunk — which is the whole backlog we have ever measured:
	//
	//   threads   worst backlog seen   threads × chunk
	//        4          3.5 MB              4.0 MB
	//        8          7.3 MB              8.0 MB
	//       16         13.2 MB             16.0 MB
	//       32         29.5 MB             32.0 MB
	//
	// So `only 94% of uploaded bytes were confirmed by the server` fired on
	// every 32-thread run and was FALSE every time: at a fixed rate the tail
	// grows with the thread count while the window's bytes do not, so the
	// warning was really a function of the knob.
	//
	// ⚖️ The ratio itself is still reported — it is a fact, and it is what
	// caught the Frankfurt 307 endpoint (45.8 MB of backlog against ZERO
	// confirmed, a ratio no cancellation tail can explain). Only the VERDICT
	// is gated, on backlog the tail cannot account for.
	p.BacklogTailBytes = int64(threads) * uploadChunkBytes
	unexplained := p.BacklogBytes - p.BacklogTailBytes
	if p.ConfirmedRatio > 0 && p.ConfirmedRatio < 0.95 && unexplained > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"only %.0f%% of uploaded bytes were confirmed by the server — %.1f MB more backlog "+
				"than %d cancelled chunks can explain", p.ConfirmedRatio*100,
			float64(unexplained)/1e6, threads))
	}
	return p
}

// setRaw is the single writer of RawMbps.
func setRaw(p Phase, bytes int64, sec float64) Phase {
	switch {
	case bytes <= 0:
		p.RawMbps = 0
		p.Warnings = append(p.Warnings, "nothing moved in the measurement window")
	case sec < minRateWindow:
		p.RawMbps = 0
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"the measurement window was %.2fs — too short to state a rate from", sec))
	default:
		p.RawMbps = float64(bytes) * 8 / sec / 1e6
	}
	return p
}

// applyConnStats records how many TCP connections the phase really used.
func applyConnStats(p Phase, used, dials, threads int, warm bool) Phase {
	p.ConnsUsed, p.Dials = used, dials

	// 🚨 AN UNPRIMED PHASE CANNOT BE READ AS A FLOW COUNT AT ALL. Go dials once
	// per concurrent request from an empty pool — the thundering herd — so it
	// reports N connections whether the transport multiplexes or not. Measured
	// against a server offering HTTP/2: primed reads 1 and warns, unprimed reads
	// 8 and says nothing. Staying silent here would be the same defect priming
	// exists to fix, arriving down a path nobody watches.
	if !warm {
		p.Warnings = append(p.Warnings,
			"the connection pool was empty when this phase started, so the connection count "+
				"below cannot tell one flow from many — do not read it as a flow count")
		return p
	}
	if threads > 1 && used > 0 && used < threads {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"asked for %d threads but only %d TCP connections carried the data — "+
				"this is not a %d-flow measurement", threads, used, threads))
	}
	return p
}

// measure turns one phase into its figures, EXCEPT RawMbps — that belongs to
// applyWindow, which knows the window. The library figure is taken as reported.
func measure(libBytesPerSec float64, bytes int64, start, end time.Time, isUpload bool) Phase {
	// ActualSec comes from the wrapper's own clock rather than the engine's
	// TestDuration so that it shares one clock with the warm-up split. The two
	// bracket the same call and agree to milliseconds.
	sec := end.Sub(start).Seconds()
	if sec <= 0 {
		sec = 0.001
	}
	lib := libBytesPerSec * 8 / 1e6
	implied := 0.0
	if lib > 0 {
		implied = float64(bytes) * 8 / 1e6 / lib
	}
	// A phase that moved nothing is NOT "consistent" — there is simply nothing to
	// compare, and letting the flag stand green on an empty run is how a broken
	// endpoint would slip past a caller that checks the flag and not the bytes.
	consistent := bytes > 0 && lib > 0
	if consistent && implied > 0 && sec > 0 {
		r := implied / sec
		consistent = r > 0.75 && r < 1.25
	}
	p := Phase{
		LibraryMbps: lib,
		Bytes:       bytes,
		ActualSec:   sec,
		ImpliedSec:  implied,
		Consistent:  consistent,
	}
	// The backlog and the confirmation ratio belong to applyWindow, which knows
	// the window: see confirmRatio.
	if isUpload && bytes == 0 {
		p.Warnings = append(p.Warnings, "the server confirmed NOTHING — the endpoint may be redirecting or rejecting uploads")
	}
	// Two different failures, two different sentences. An empty phase is already
	// explained by the warning above; adding "the estimator is weighted to the
	// last seconds" there would offer a true statement about the engine as if it
	// were the reason nothing moved.
	if !consistent && bytes > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"the reported rate implies %.1fs of data but the phase ran %.1fs — the engine's estimator is weighted to the last seconds, so treat the raw figure as the average",
			implied, sec))
	}
	return p
}
