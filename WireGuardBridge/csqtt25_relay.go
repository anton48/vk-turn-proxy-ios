package main

// A csqtt 2.5 stream's TURN allocation — the bridge's OWN.
//
// This is a second instance of what csqtt.DialRelay does for the 2.1.9
// workers, kept apart on purpose: pkg/csqtt is 2.1.9's and is not touched for
// 2.5. The two are kept in step BY HAND — a fix to either one's dial, close or
// deadline is read against the other.
//
// What 2.5 needs beyond a copy: the engine bounds every write with a deadline
// on the conn it is given (csqtt25.ClientConfig.WriteBound), and pion's
// relayed conn ignores one — its SetWriteDeadline is a stub. The deadline
// belongs on the CONTROL socket the allocation rides on (a TCP connection to
// the relay, or a UDP socket): that is where a write waits when the relay
// stops taking bytes. csqtt25Relay.packetConn hands the engine the relayed
// conn with its write deadline put there.

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
)

// csqtt25RelayCloseBudget bounds the ONE write pion makes when an allocation
// is closed — the deallocate — on the control socket: over TCP a relay that
// stopped taking bytes would otherwise hold the close, and with it the
// stream's teardown and the stop, for ever. It also ends a data write parked
// on that socket.
const csqtt25RelayCloseBudget = 500 * time.Millisecond

// csqtt25Relay is one allocation: the relayed conn to write to the server
// through, and the control socket under it.
type csqtt25Relay struct {
	relayed net.PacketConn
	ctl     net.PacketConn
	closing atomic.Bool // Close under way: a deadline cleared now leaves the close's own in place
	close   func()
	once    sync.Once
	// dealloc is what the relay said to the close's confirmed deallocate, plus
	// one — 0 while nothing was asked (a TCP leg, a close not yet made).
	dealloc atomic.Int32
}

// deallocated reports what the relay said when the close ASKED it to release
// the allocation — csqtt.Relay.Deallocate's twin; asked is false over TCP and
// before Close has returned.
func (r *csqtt25Relay) deallocated() (v csqtt.Deallocate, asked bool) {
	n := r.dealloc.Load()
	return csqtt.Deallocate(n - 1), n != 0
}

// Close ends the allocation: the deallocate under a bounded write, the TURN
// client, the control socket. Idempotent.
func (r *csqtt25Relay) Close() {
	r.closing.Store(true) // before the close sets its deadline
	r.once.Do(r.close)
}

// packetConn is the allocation as the engine's socket: the relayed conn's
// reads and writes, and a write deadline that is REAL.
func (r *csqtt25Relay) packetConn() net.PacketConn {
	return csqtt25RelayConn{PacketConn: r.relayed, r: r}
}

type csqtt25RelayConn struct {
	net.PacketConn
	r *csqtt25Relay
}

// deallocated is the allocation's word for whoever closes it through the
// engine's closer and holds only this conn (csqtt25_bridge.go's dialer).
func (c csqtt25RelayConn) deallocated() (csqtt.Deallocate, bool) { return c.r.deallocated() }

// SetWriteDeadline puts the deadline on the control socket. The engine sets
// it before a write and clears it behind it; a clearing that comes while the
// allocation is being closed puts the close's own budget back — the close set
// it first, and wiped, the deallocate would be left unbounded on the very
// socket that is stuck.
//
// 🚫 The clearing and the close do not take turns, so «is a close under way»
// is asked BEHIND the clearing — as csqtt.Relay.write asks it — and not only
// in front of it: a clearing that looked first and reached the socket after
// the close had set its deadline there would wipe it. Asked in front as well,
// a close already known never sees its deadline taken off even for a moment.
func (c csqtt25RelayConn) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		return c.r.ctl.SetWriteDeadline(t)
	}
	if c.r.closing.Load() {
		return c.r.ctl.SetWriteDeadline(time.Now().Add(csqtt25RelayCloseBudget))
	}
	err := c.r.ctl.SetWriteDeadline(time.Time{})
	if c.r.closing.Load() { // the close began beside the clearing
		return c.r.ctl.SetWriteDeadline(time.Now().Add(csqtt25RelayCloseBudget))
	}
	return err
}

// csqtt25CloseRelay is csqtt.closeRelayBounded's twin: the write budget, then —
// over a UDP leg — the relay ASKED whether it released the allocation (confirm,
// under its own budget, the write budget set anew behind it), then the relayed
// conn's own close, the TURN client, the control socket.
func csqtt25CloseRelay(ctl net.PacketConn, relayed io.Closer, tcClose func(), confirm func()) {
	_ = ctl.SetWriteDeadline(time.Now().Add(csqtt25RelayCloseBudget))
	if confirm != nil {
		confirm()
		_ = ctl.SetWriteDeadline(time.Now().Add(csqtt25RelayCloseBudget))
	}
	_ = relayed.Close()
	if tcClose != nil {
		tcClose()
	}
	_ = ctl.Close()
}

// csqtt25DialRelay allocates a relay and creates a permission for the server.
// transport is "tcp" (what the app ships on) or "udp".
//
// The local socket is udp4 / tcp4 and the address family is STATED: from a
// dual-stack listener pion infers IPv6 and asks for an IPv6 allocation, which
// VK's relay answers with silence.
//
// allocated, when not nil, is called the moment the relay has ACCEPTED the
// Allocate — before the permission, where the fact becomes true: whatever
// fails behind it, the seat was used, and the credential's lease has to know
// (the relay keeps a given-back seat on the quota for a second more).
//
// The errors are worded as csqtt.DialRelay words them: whoever reads a
// failed dial's text reads the same text for either protocol.
//
// 🚫 ctx ENDS the dial — the one thing csqtt.DialRelay has no counterpart of:
// a path change must not wait for a relay that will not answer on the path
// that is gone (a TCP connect: five seconds; an Allocate: pion's whole ladder
// of repeats). An ended dial fails like any other — whoever ended it knows by
// its own context that this was no word about the relay — and an allocation
// the relay had already accepted is given back under the close's budget.
func csqtt25DialRelay(ctx context.Context, creds csqtt.TURNCredentials, server *net.UDPAddr, transport string, allocated func()) (*csqtt25Relay, error) {
	var ctl net.PacketConn
	switch transport {
	case "udp":
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, fmt.Errorf("local udp: %w", err)
		}
		ctl = uc
	case "tcp":
		tcp, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", creds.Address)
		if err != nil {
			return nil, fmt.Errorf("dial tcp to relay: %w", err)
		}
		ctl = turn.NewSTUNConn(tcp)
	default:
		return nil, fmt.Errorf("unknown TURN transport %q", transport)
	}
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelWarn
	family := turn.RequestedAddressFamilyIPv4
	if server != nil && server.IP.To4() == nil {
		family = turn.RequestedAddressFamilyIPv6
	}
	tc, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr:         creds.Address,
		Conn:                   ctl,
		Username:               creds.Username,
		Password:               creds.Password,
		Realm:                  "okcdn.ru",
		Software:               "vk-turn-srtp",
		LoggerFactory:          lf,
		RequestedAddressFamily: family,
	})
	if err != nil {
		_ = ctl.Close()
		return nil, fmt.Errorf("turn.NewClient: %w", err)
	}
	if err := tc.Listen(); err != nil {
		tc.Close()
		_ = ctl.Close()
		return nil, fmt.Errorf("turn listen: %w", err)
	}
	// From here the dial waits for the relay's answers: once ctx is done those
	// waits are failed, for as long as the dial lasts.
	stop := csqtt25EndWaitsOn(ctx, tc)
	defer stop()
	relayed, err := tc.Allocate()
	if err != nil {
		stop()
		tc.Close()
		_ = ctl.Close()
		return nil, fmt.Errorf("turn allocate: %w", err)
	}
	if allocated != nil {
		allocated()
	}
	if ctx.Err() != nil {
		// Accepted, and ended: the seat was used — it is given back, under the
		// close's budget, and no permission is asked on a dial that is over.
		stop()
		csqtt25CloseRelay(ctl, relayed, tc.Close, nil) // an ended dial waits for no answer
		return nil, csqtt25Unreleased(transport, csqtt.DeallocateNotAwaited, fmt.Errorf("relay dial ended behind its allocation: %w", context.Cause(ctx)))
	}
	if err := tc.CreatePermission(server); err != nil {
		stop()
		failure := fmt.Errorf("turn create permission: %w", err)
		if transport != "udp" {
			_ = relayed.Close()
			tc.Close()
			_ = ctl.Close()
			return nil, failure
		}
		// The allocation was accepted: it holds a seat whether a stream ever
		// rode it or not. A dial that was ENDED gives it back and waits for no
		// answer; one that failed by itself has no hurry and asks the relay, as
		// a close does. Either way a release the relay did not confirm is SAID.
		v := csqtt.DeallocateNotAwaited
		if ctx.Err() != nil {
			csqtt25CloseRelay(ctl, relayed, tc.Close, nil)
		} else {
			csqtt25CloseRelay(ctl, relayed, tc.Close, func() { v = csqtt.ConfirmDeallocate(tc, creds.Username, creds.Password) })
		}
		return nil, csqtt25Unreleased(transport, v, failure)
	}
	r := &csqtt25Relay{relayed: relayed, ctl: ctl}
	// Over UDP the close asks the relay whether it released the allocation and
	// keeps the answer for the lease (csqtt_ghost.go); over TCP the connection's
	// close does it. The conversation is pkg/csqtt's (csqtt.ConfirmDeallocate).
	var confirm func()
	if transport == "udp" {
		confirm = func() { r.dealloc.Store(int32(csqtt.ConfirmDeallocate(tc, creds.Username, creds.Password)) + 1) }
	}
	r.close = func() { csqtt25CloseRelay(ctl, relayed, tc.Close, confirm) }
	return r, nil
}

// csqtt25Unreleased is a dial's failure behind an ACCEPTED allocation, with what
// became of that allocation's deallocate: over UDP a release the relay did not
// confirm (v out of reach) makes the failure a csqtt.UnreleasedError — worded as
// the failure itself — for the dialer to tell the lease; a confirmed release,
// and every failure over TCP, is the plain failure.
func csqtt25Unreleased(transport string, v csqtt.Deallocate, failure error) error {
	if transport == "udp" && v.OutOfReach() {
		return &csqtt.UnreleasedError{Err: failure, Deallocate: v}
	}
	return failure
}

// csqtt25DialEndEvery: how often an ended dial's waits are failed again.
const csqtt25DialEndEvery = 20 * time.Millisecond

// csqtt25EndWaitsOn fails the TURN client's waiting transactions once ctx is
// done — and again every csqtt25DialEndEvery until stop. Again, because pion's
// Close fails what waits at that moment and nothing registered a moment later:
// an Allocate is two transactions, a permission follows it, and one that
// begins behind a single Close would run its whole ladder of repeats. stop
// returns when nothing more will be closed; it may be called more than once.
func csqtt25EndWaitsOn(ctx context.Context, tc interface{ Close() }) (stop func()) {
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
		case <-done:
			return
		}
		again := time.NewTicker(csqtt25DialEndEvery)
		defer again.Stop()
		for {
			tc.Close()
			select {
			case <-done:
				return
			case <-again.C:
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		<-exited
	}
}
