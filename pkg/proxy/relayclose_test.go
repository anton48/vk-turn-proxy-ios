package proxy

// The writes a session's teardown makes on the control socket have no
// deadline of their own: pion's deallocate when the allocation is closed,
// and before it DTLS's close_notify (pion/dtls writes it synchronously with a
// background context) through the SRTP wrapper and the relay. On a TCP relay
// that stopped taking bytes each blocks for ever, and so does whoever closes
// the session — after a path change, the restart. Verified with a real pion
// allocation and a blocked WriteTo on 2026-09-06 (hung after three seconds,
// ended only by forcing the control socket shut). The session's Close puts
// ONE absolute write deadline on the socket we own before ANY of them.

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// blockedCtl is a control socket whose writes hang until a write deadline
// set BEFORE OR DURING the hang passes, or the socket is closed — a full TCP
// buffer toward a dead relay.
type blockedCtl struct {
	net.PacketConn
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
	closed   chan struct{}
	once     sync.Once
}

func newBlockedCtl(t *testing.T) *blockedCtl {
	t.Helper()
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return &blockedCtl{PacketConn: uc, changed: make(chan struct{}), closed: make(chan struct{})}
}

func (b *blockedCtl) SetWriteDeadline(t time.Time) error {
	b.mu.Lock()
	b.deadline = t
	close(b.changed)
	b.changed = make(chan struct{})
	b.mu.Unlock()
	return nil
}

func (b *blockedCtl) WriteTo([]byte, net.Addr) (int, error) {
	for {
		b.mu.Lock()
		deadline, changed := b.deadline, b.changed
		b.mu.Unlock()
		var expire <-chan time.Time
		if !deadline.IsZero() {
			expire = time.After(time.Until(deadline))
		}
		select {
		case <-b.closed:
			return 0, net.ErrClosed
		case <-expire:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
		}
	}
}

func (b *blockedCtl) Close() error {
	b.once.Do(func() { close(b.closed) })
	return b.PacketConn.Close()
}

// deallocatingRelay is pion's relay conn as Close sees it: Close WRITES the
// deallocate through the control socket.
type deallocatingRelay struct {
	net.PacketConn
	ctl net.PacketConn
}

func (d deallocatingRelay) Close() error {
	_, err := d.ctl.WriteTo([]byte("deallocate"), nil)
	return err
}

type noopCloser struct{}

func (noopCloser) Close()                                {}
func (noopCloser) SendBindingRequest() (net.Addr, error) { return nil, nil }

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

// The SRTP session's Close returns within the deallocate budget when the
// control socket's writes hang. Sabotage seen red: the SetWriteDeadline
// before relayConn.Close dropped (Close never returns).
func TestSRTPSessionCloseIsBoundedWhenTheDeallocateBlocks(t *testing.T) {
	ctl := newBlockedCtl(t)
	s := &srtpSessionConn{
		Conn:      nopConn{},
		relayConn: deallocatingRelay{PacketConn: ctl, ctl: ctl},
		tc:        noopCloser{},
		ctlConn:   ctl,
	}
	done := make(chan struct{})
	t0 := time.Now()
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(relayCloseWriteBudget + 2*time.Second):
		t.Fatal("srtpSessionConn.Close did not return: the deallocate write hung it")
	}
	if took := time.Since(t0); took < relayCloseWriteBudget/2 {
		t.Fatalf("Close returned in %s — it did not even try the deallocate under its deadline", took)
	}
}

// closeNotifyConn is the DTLS/SRTP conn as Close sees it: pion's Close
// WRITES a close_notify through the relay — here, like the deallocate,
// through the control socket.
type closeNotifyConn struct {
	net.Conn
	ctl net.PacketConn
}

func (c closeNotifyConn) Close() error {
	_, err := c.ctl.WriteTo([]byte("close_notify"), nil)
	return err
}

// The SRTP session's Close returns within ONE budget when the control
// socket's writes hang: the close_notify and the deallocate share the
// absolute deadline set before either of them. Sabotage seen red: the
// deadline moved back after s.Conn.Close (the close_notify hangs for ever —
// the shape the user's review found on 2026-09-07).
func TestSRTPSessionCloseIsBoundedWhenTheCloseNotifyBlocks(t *testing.T) {
	ctl := newBlockedCtl(t)
	s := &srtpSessionConn{
		Conn:      closeNotifyConn{ctl: ctl},
		relayConn: deallocatingRelay{PacketConn: ctl, ctl: ctl},
		tc:        noopCloser{},
		ctlConn:   ctl,
	}
	done := make(chan struct{})
	t0 := time.Now()
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(relayCloseWriteBudget + 2*time.Second):
		t.Fatal("srtpSessionConn.Close did not return: the close_notify write hung it")
	}
	took := time.Since(t0)
	if took < relayCloseWriteBudget/2 {
		t.Fatalf("Close returned in %s — it did not even try the close_notify under its deadline", took)
	}
	if took > relayCloseWriteBudget+300*time.Millisecond {
		t.Fatalf("Close took %s — the close_notify and the deallocate must share ONE deadline, not pay two", took)
	}
}
