// Package speedtest wraps showwin/speedtest-go for the iOS app's in-app speed
// test. It runs in the APP, never in the network extension: a 32-flow generator
// next to the extension's ~50 MB jetsam budget is what builds 130-146 were about.
//
// Design notes that are not obvious from the code:
//
//   - ONE RUN PER PROCESS. The guard lives here, at package scope, not in a view
//     model: a guard scoped to one object cannot protect a process-wide resource,
//     which is exactly how build 271 ended up with two concurrent load runs.
//
//   - POLLED, NOT CALLBACK-DRIVEN. Progress crosses into Swift by polling a
//     snapshot rather than by a cgo callback. The app already polls stats, and it
//     keeps the C surface to four plain functions.
//
//   - TWO RESULTS, ALWAYS. The library reports a blended estimator
//     (0.5*EWMA + 0.5*mean of the last 5 s) whose value depends on how long the
//     phase actually ran; we also compute raw = confirmed bytes / actual elapsed.
//     Only the raw figure is comparable across different thread counts and
//     durations, which is the whole point of exposing those knobs.
//
//   - EARLY STOP CANNOT BE DISABLED. The library ends a phase once the rate is
//     stable (CV < 3%), and its Welford window is hardcoded at 5 s inside an
//     `internal/` package. So `Duration` is a CEILING; the ACTUAL per-phase
//     duration is measured and reported, and the raw metric is computed over it.
package speedtest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	stgo "github.com/showwin/speedtest-go/speedtest"
)

// EngineVersion is reported beside every result so a number can be traced to the
// code that produced it. v1.7.10 counted ATTEMPTED upload bytes (they were added
// as the transport read the request body, before the server confirmed); 1.7.11
// splits that into a separate read-volume accumulator. Do not go back.
const EngineVersion = "speedtest-go v1.7.11"

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
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Sponsor  string  `json:"sponsor"`
	Country  string  `json:"country"`
	Host     string  `json:"host"`
	Distance float64 `json:"distance_km"`
	LatencyM float64 `json:"latency_ms"`
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
	// WarmupSec is non-zero only in research mode: the seconds discarded before
	// the measurement window opened. RawMbps then covers the window ALONE, which
	// is what makes two runs at different thread counts comparable.
	WarmupSec  float64 `json:"warmup_sec"`
	ImpliedSec float64 `json:"implied_sec"`
	Consistent bool    `json:"consistent"`

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
	Down         Phase   `json:"download"`
	Up           Phase   `json:"upload"`
	Engine       string  `json:"engine"`
	Estimator    string  `json:"estimator"`
}

var (
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	snap    Progress
)

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

// Servers fetches the selectable list. NOTE: the list is built from this
// device's APPARENT IP, so with the tunnel up it describes servers near the
// EXIT and with it down servers near the user. The caller must say which,
// because the same "auto" otherwise measures two different paths silently.
func Servers(ctx context.Context) ([]ServerInfo, error) {
	client := stgo.New()
	if _, err := client.FetchUserInfoContext(ctx); err != nil {
		return nil, fmt.Errorf("fetch user info: %w", err)
	}
	list, err := client.FetchServerListContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch server list: %w", err)
	}
	out := make([]ServerInfo, 0, len(list))
	for _, s := range list {
		out = append(out, ServerInfo{
			ID:       s.ID,
			Name:     s.Name,
			Sponsor:  s.Sponsor,
			Country:  s.Country,
			Host:     s.Host,
			Distance: s.Distance,
		})
	}
	return out, nil
}

// Start begins a run. It refuses if one is already in flight — the refusal is
// the point: two concurrent generators would measure each other.
func Start(cfg Config) error {
	mu.Lock()
	if running {
		mu.Unlock()
		return fmt.Errorf("a speed test is already running")
	}
	running = true
	ctx, c := context.WithCancel(context.Background())
	cancel = c
	snap = Progress{
		State:     "running",
		Stage:     "ping",
		Threads:   cfg.Threads,
		Requested: cfg.DurationSec,
		Engine:    EngineVersion,
		Estimator: "EWMA5",
		ServerID:  cfg.ServerID,
	}
	mu.Unlock()

	go func() {
		defer func() {
			mu.Lock()
			running = false
			cancel = nil
			mu.Unlock()
		}()
		if err := run(ctx, cfg); err != nil {
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

func run(ctx context.Context, cfg Config) error {
	threads := cfg.Threads
	if threads < 1 {
		threads = 1
	}
	client := stgo.New(stgo.WithUserConfig(&stgo.UserConfig{MaxConnections: threads, Debug: cfg.Debug}))

	user, err := client.FetchUserInfoContext(ctx)
	if err != nil {
		return fmt.Errorf("fetch user info: %w", err)
	}
	setSnap(func(p *Progress) {
		p.OoklaSeesIP = user.IP
		p.OoklaSeesISP = user.Isp
	})
	list, err := client.FetchServerListContext(ctx)
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
		target, err = client.FetchServerByIDContext(ctx, cfg.ServerID)
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

	// Duration is a CEILING: the library ends a phase early once the rate is
	// stable, and that cannot be switched off from outside the package.
	if cfg.DurationSec > 0 {
		d := time.Duration(cfg.DurationSec) * time.Second
		if cfg.Research {
			// The window must OPEN after the warm-up, so the capture has to
			// cover both. And the engine's stability cut-off has to go, or the
			// phase ends at ~10 s regardless of what was asked for and the
			// "fixed window" is not fixed.
			d += researchWarmup
			client.SetEarlyStop(false)
		}
		client.SetCaptureTime(d)
	}
	client.SetNThread(threads)

	setSnap(func(p *Progress) { p.Stage = "ping" })
	if err := target.PingTestContext(ctx, nil); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	setSnap(func(p *Progress) { p.PingMs = float64(target.Latency.Milliseconds()) })

	wantDown := cfg.Direction == "download" || cfg.Direction == "both" || cfg.Direction == ""
	wantUp := cfg.Direction == "upload" || cfg.Direction == "both" || cfg.Direction == ""

	if wantDown {
		setSnap(func(p *Progress) { p.Stage = "download" })
		start := time.Now()
		wb, wat, err := runPhase(ctx, cfg.Research,
			&int64Reader{read: func() int64 { return target.Context.GetTotalDownload() }},
			target.DownloadTestContext)
		if err != nil {
			return fmt.Errorf("download: %w", err)
		}
		phase := measure(float64(target.DLSpeed), target.Context.GetTotalDownload(), start, target.TestDuration.Download, 0, 0, false)
		phase = applyWarmup(phase, wb, wat, target.Context.GetTotalDownload())
		setSnap(func(p *Progress) { p.Down = phase })
	}
	if wantUp {
		setSnap(func(p *Progress) { p.Stage = "upload" })
		start := time.Now()
		wb, wat, err := runPhase(ctx, cfg.Research,
			&int64Reader{read: func() int64 { return target.Context.GetTotalUpload() }},
			target.UploadTestContext)
		if err != nil {
			return fmt.Errorf("upload: %w", err)
		}
		phase := measure(float64(target.ULSpeed), target.Context.GetTotalUpload(), start, target.TestDuration.Upload,
			target.Context.GetUploadBacklog(), target.Context.GetUploadConfirmationRatio(), true)
		phase = applyWarmup(phase, wb, wat, target.Context.GetTotalUpload())
		setSnap(func(p *Progress) { p.Up = phase })
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
func resolveUploadURL(ctx context.Context, raw string) string {
	client := &http.Client{
		Timeout: 15 * time.Second,
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

// runPhase executes one direction and, in research mode, samples the byte
// counter at the warm-up boundary so the raw figure covers the measurement
// window alone.
func runPhase(ctx context.Context, research bool, total *int64Reader, run func(context.Context) error) (warmBytes int64, warmAt time.Time, err error) {
	if !research {
		return 0, time.Time{}, run(ctx)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-time.After(researchWarmup):
			warmBytes = total.read()
			warmAt = time.Now()
		case <-done:
		case <-ctx.Done():
		}
	}()
	err = run(ctx)
	close(done)
	return warmBytes, warmAt, err
}

// applyWarmup rewrites the raw figure to cover the measurement window only.
// Called with a zero warmAt outside research mode, where it does nothing.
func applyWarmup(p Phase, warmBytes int64, warmAt time.Time, endBytes int64) Phase {
	if warmAt.IsZero() {
		return p
	}
	window := time.Since(warmAt).Seconds()
	if window <= 0 {
		return p
	}
	p.WarmupSec = researchWarmup.Seconds()
	p.RawMbps = float64(endBytes-warmBytes) * 8 / window / 1e6
	if endBytes-warmBytes <= 0 {
		p.Warnings = append(p.Warnings, "nothing moved after the warm-up — the measurement window is empty")
	}
	return p
}

// int64Reader is a tiny indirection so runPhase can sample either direction's
// counter without knowing which.
type int64Reader struct{ read func() int64 }

// measure turns one phase into both numbers. The library figure is taken as
// reported; the raw one is bytes over the ACTUAL elapsed time, which is the only
// figure comparable across thread counts and durations.
func measure(libBytesPerSec float64, bytes int64, start time.Time, reported *time.Duration, backlog int64, ratio float64, isUpload bool) Phase {
	elapsed := time.Since(start)
	if reported != nil && *reported > 0 {
		elapsed = *reported
	}
	sec := elapsed.Seconds()
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
		ratio := implied / sec
		consistent = ratio > 0.75 && ratio < 1.25
	}
	p := Phase{
		LibraryMbps: lib,
		RawMbps:     float64(bytes) * 8 / sec / 1e6,
		Bytes:       bytes,
		ActualSec:   sec,
		ImpliedSec:  implied,
		Consistent:  consistent,
	}
	if isUpload {
		p.BacklogBytes = backlog
		p.ConfirmedRatio = ratio
		if ratio > 0 && ratio < 0.95 {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"only %.0f%% of uploaded bytes were confirmed by the server", ratio*100))
		}
		if bytes == 0 {
			p.Warnings = append(p.Warnings, "the server confirmed NOTHING — the endpoint may be redirecting or rejecting uploads")
		}
	}
	// Two different failures, two different sentences. An empty phase is already
	// explained by the warning above; adding "the estimator is weighted to the
	// last seconds" there would offer a true statement about the engine as if it
	// were the reason nothing moved.
	if !consistent && bytes > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"the reported rate implies %.1fs of data but the phase ran %.1fs — the engine's estimator is weighted to the last seconds, so treat the raw figure as the average",
			implied, sec))
	} else if !consistent && bytes == 0 && lib <= 0 {
		p.Warnings = append(p.Warnings, "this phase moved no data at all")
	}
	return p
}
