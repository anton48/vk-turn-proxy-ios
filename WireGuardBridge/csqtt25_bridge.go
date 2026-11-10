package main

// csqtt 2.5 behind the csqtt handle (2026-11-10).
//
// 2.5 is another protocol than 2.1.9 — a 2.5 server answers a 2.1.9 client
// with silence and the other way round — so the profile says which one its
// server speaks ("csqtt_generation"), and csqttStart picks the engine. What
// Swift sees does not change: the same exports, the same handle, the same
// provision, stats and terminal reasons. This file is the adapter that makes
// pkg/csqtt25's client a csqttClient:
//
//   - a stream's socket is a TURN allocation opened with the SAME credential
//     lease as a 2.1.9 worker's (csqttPoolAdapter): the lease hears of its
//     allocation the moment the relay accepts it, of a refusal with the moment
//     the dial began, and is given back right behind the relay's close;
//   - what the server sends down is queued for the TUN pump, bounded;
//   - a path change reaches the engine (a new identity, every stream again);
//   - the wake hook reaches it too (a freeze boundary: every ready stream is
//     asked afresh — the engine's own rules, pkg/csqtt25/liveness.go);
//   - a stream's write is BOUNDED (csqtt25.DefaultWriteBound): the socket the
//     engine gets is the bridge's own allocation, whose write deadline is real
//     (csqtt25_relay.go — pion's relayed conn ignores one).

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt25"
)

// The profile's names for the two protocols.
const (
	csqttGen219 = "2.1.9"
	csqttGen25  = "2.5"
)

// csqtt25MTU is the tunnel MTU 2.5 is PROVISIONED with — the reference's: a
// packet above csqtt25.WholeMax travels as two datagrams on one stream and is
// put together on the far side. It is not what the interface gets: the app
// bounds a provisioned MTU as it bounds the user's own (TunnelMTU, 1000…1400),
// so a phone runs 2.5 at 1400 unless the user set a lower one by hand, which
// wins — and at anything above WholeMax every full-size packet is two
// datagrams.
const csqtt25MTU = 1500

// csqtt25DownQueue bounds what waits between the streams' read loops and the
// TUN pump; a packet that finds it full is dropped and counted (2.1.9's own
// out-queue has the same size).
const csqtt25DownQueue = 1024

// csqttGeneration reads the config's generation: gen25 for "2.5"; an absent
// field is 2.1.9, what every config before the field meant. known is false
// for a name this build does not have — the start is refused rather than
// guessed: the wrong protocol is a tunnel that never comes up.
func csqttGeneration(name string) (gen25, known bool) {
	switch name {
	case "", csqttGen219:
		return false, true
	case csqttGen25:
		return true, true
	}
	return false, false
}

// csqtt25Workers keeps the asked stream count inside what a 2.5 server takes.
func csqtt25Workers(n int) int {
	if n < csqtt25.MinWorkers {
		return csqtt25.MinWorkers
	}
	if n > csqtt25.MaxWorkers {
		return csqtt25.MaxWorkers
	}
	return n
}

// csqtt25Engine is what the adapter needs from csqtt25.Client — an interface
// so that it can be tested against a fake on the host.
type csqtt25Engine interface {
	Send(pkt []byte) error
	Close()
	Stats() csqtt25.Stats
	Config() csqtt25.ConfigResponse
	OnPathChange()
	Wake()
	Done() <-chan struct{}
	Err() error
}

// csqtt25DialEngine is csqtt25.Dial behind a variable, replaceable by tests.
var csqtt25DialEngine = func(ctx context.Context, cfg csqtt25.ClientConfig) (csqtt25Engine, error) {
	c, err := csqtt25.Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// csqtt25OpenRelay opens one stream's TURN allocation toward the server —
// the same kind of allocation the 2.1.9 workers ride (the relay knows nothing
// of what it carries), opened by the bridge's own dial (csqtt25_relay.go) and
// handed over as a conn whose write deadline is real: the engine bounds every
// write with it. Behind a variable for the tests.
var csqtt25OpenRelay = func(creds csqtt.TURNCredentials, server *net.UDPAddr, transport string, allocated func()) (net.PacketConn, func(), error) {
	r, err := csqtt25DialRelay(creds, server, transport, allocated)
	if err != nil {
		return nil, nil, err
	}
	return r.packetConn(), r.Close, nil
}

// csqtt25Client is a csqtt25 engine as the bridge's csqttClient.
type csqtt25Client struct {
	eng      csqtt25Engine // set once, before the client is handed to anyone
	down     chan []byte
	dropped  atomic.Int64
	allocRTT atomic.Int64 // the last relay allocation, ns
}

// csqtt25Start dials a 2.5 client: lease is the pool adapter's creds.
func csqtt25Start(ctx context.Context, cfg csqttConfig, server *net.UDPAddr, transport string,
	lease func(context.Context, int) (csqtt.Credential, error)) (csqttClient, error) {
	a := &csqtt25Client{down: make(chan []byte, csqtt25DownQueue)}
	eng, err := csqtt25DialEngine(ctx, csqtt25.ClientConfig{
		Password: cfg.Password,
		Workers:  cfg.NumConns,
		Mode:     csqtt25.ModeUnified,
		Keys:     csqtt25.KeysAuto,
		Dial:     a.dialer(server, transport, lease),
		Deliver:  a.deliver,
		// Always bounded: a relay that stops taking bytes costs its own stream
		// the bound once, never the TUN pump until somebody notices.
		WriteBound: csqtt25.DefaultWriteBound,
		// The engine's lines say whose they are themselves ("csqtt25: …").
		Logf: log.Printf,
	})
	if err != nil {
		return nil, csqtt25Err(err)
	}
	a.eng = eng
	return a, nil
}

// dialer is the engine's DialFunc. The order is the 2.1.9 worker's: the lease
// first; the moment the dial begins taken BEHIND the lease (a worker can park
// on the pool for minutes, and the relay's health is judged by when the dial
// began); Allocated the moment the relay accepts; a refusal told to the lease
// before it goes back; and on the way out the relay closed — the deallocate
// written — BEFORE the lease is released (the pool then counts the seat for
// the relay's second).
func (a *csqtt25Client) dialer(server *net.UDPAddr, transport string,
	lease func(context.Context, int) (csqtt.Credential, error)) csqtt25.DialFunc {
	return func(ctx context.Context, workerID int) (net.PacketConn, net.Addr, func(), error) {
		cred, err := lease(ctx, workerID)
		if err != nil {
			return nil, nil, nil, err
		}
		began := time.Now()
		conn, closeRelay, err := csqtt25OpenRelay(cred.TURNCredentials, server, transport, func() { cred.Allocated(began) })
		if err != nil {
			cred.Failed(err, began)
			cred.Release()
			return nil, nil, nil, err
		}
		a.allocRTT.Store(int64(time.Since(began)))
		return conn, server, func() {
			closeRelay()
			cred.Release()
		}, nil
	}
}

// deliver is the engine's Deliver: called from every stream's read loop, it
// never waits for the TUN.
func (a *csqtt25Client) deliver(pkt []byte) {
	select {
	case a.down <- pkt:
	default:
		a.dropped.Add(1)
	}
}

func (a *csqtt25Client) WritePacket(pkt []byte) error { return a.eng.Send(pkt) }

func (a *csqtt25Client) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-a.down:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.eng.Done():
		return nil, errors.New("csqtt 2.5: the client is over")
	}
}

func (a *csqtt25Client) Close() error {
	a.eng.Close()
	return nil
}

// Stats is the engine's counters under the names the bridge reads for the
// app: connections are the LIVE streams of the count the server agreed to.
func (a *csqtt25Client) Stats() csqtt.Stats {
	s := a.eng.Stats()
	return csqtt.Stats{
		TxBytes: s.TxBytes, RxBytes: s.RxBytes,
		Ready: s.Ready, Live: s.Live, Total: s.Target,
		Restarts: s.Restarts, AllocateRTT: time.Duration(a.allocRTT.Load()),
		PathChanges: s.PathChanges, Repairs: s.Repairs, Probes: s.Probes,
		Dropped: a.dropped.Load(), NoWorker: s.NoStream,
	}
}

// StatsLine is 2.5's wording of its counters — the ONE place, read by the
// path-event snapshot, the once-a-minute line and the stop line (csqttLine).
func (a *csqtt25Client) StatsLine(tunIn, tunOut int64) string {
	s := a.eng.Stats()
	return fmt.Sprintf("2.5: workers %d/%d ready (%d heard from lately; %d asked), sessions %d, ended %d, dtls %d, fallbacks %d, probes %d, repairs %d, server restarts %d (found out behind one %d), path changes %d, freezes %d, wakes %d (silent behind either %d), write stalls %d, dead writes %d, no stream %d, auth failures %d, fragments tx=%d rx=%d, dropped %d; tun in=%d out=%d",
		s.Ready, s.Target, s.Live, s.Workers, s.Sessions, s.Restarts, s.Handshakes, s.Fallbacks, s.Probes, s.Repairs,
		s.PanelRestarts, s.Unsettled, s.PathChanges, s.Freezes, s.Wakes, s.WakeDeaf, s.WriteStalls, s.DeadWrites,
		s.NoStream, s.AuthFailures, s.FragsTx, s.FragsRx, a.dropped.Load(), tunIn, tunOut)
}

func (a *csqtt25Client) Config() csqtt.ConfigResponse {
	c := a.eng.Config()
	return csqtt.ConfigResponse{TunnelIP: c.TunnelIP, DNS: c.DNS, LocalPort: c.Port, StreamRevision: c.Stream, Raw: c.Raw}
}

func (a *csqtt25Client) OnPathChange() { a.eng.OnPathChange() }

// WakeHealthCheck is the app's wake hook: the engine's freeze boundary. It
// never waits (csqtt25.Client.Wake).
func (a *csqtt25Client) WakeHealthCheck() { a.eng.Wake() }

func (a *csqtt25Client) Done() <-chan struct{} { return a.eng.Done() }
func (a *csqtt25Client) Err() error            { return csqtt25Err(a.eng.Err()) }

// csqtt25Err gives 2.5's terminal errors the shape csqttReason reads, so the
// user is told the same thing for the same reason whichever protocol said it.
func csqtt25Err(err error) error {
	var denied *csqtt25.DeniedError
	if errors.As(err, &denied) {
		return &csqtt.DeniedError{Reason: denied.Reason}
	}
	if errors.Is(err, csqtt25.ErrNoConfig) {
		return csqtt.ErrNoConfig
	}
	return err
}
