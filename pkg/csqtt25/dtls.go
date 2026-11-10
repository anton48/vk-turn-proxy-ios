package csqtt25

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/logging"
)

// The DTLS path. A 2.5 server answers a DTLS 1.2 ClientHello on the stream's
// own socket and both ends take the wrapper's keys from the handshake's
// DTLS-SRTP exporter; nothing else of DTLS is used afterwards. The server's
// handshake is its own implementation, with a narrow acceptance: DTLS 1.2,
// ECDHE-ECDSA-AES128-GCM-SHA256, extended master secret, use_srtp with
// AES128_CM_HMAC_SHA1_80, secp256r1 among the groups, ecdsa_secp256r1_sha256
// among the signature schemes. Its certificate is self-signed and new for
// every handshake, and the reference client does not pin it: the handshake
// is NOT authenticated — it yields fresh keys, it does not prove the server.
const (
	// HandshakeTimeout and FlightInterval are the reference client's.
	HandshakeTimeout = 8 * time.Second
	FlightInterval   = 500 * time.Millisecond
)

// handshakeTimeout is HandshakeTimeout; a variable so that a test can see
// the bound act without waiting eight seconds.
var handshakeTimeout = HandshakeTimeout

// IsDTLS reports whether a datagram is a DTLS record rather than one of the
// wrapper's (RFC 7983's first-byte ranges).
func IsDTLS(wire []byte) bool { return len(wire) > 0 && wire[0] >= 20 && wire[0] <= 63 }

// Splitter shares one stream's socket between the DTLS handshake and the
// wrapper: DTLS records go to DTLSConn, everything else to Media.
type Splitter struct {
	conn  net.PacketConn
	peer  net.Addr
	dtls  chan []byte
	media chan []byte
	done  chan struct{} // closed when the socket's read ends

	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
	sealed   bool
}

// NewSplitter starts reading conn. The socket stays the caller's to close;
// closing it ends the splitter.
func NewSplitter(conn net.PacketConn, peer net.Addr) *Splitter {
	s := &Splitter{
		conn: conn, peer: peer,
		dtls: make(chan []byte, 64), media: make(chan []byte, 1024),
		done: make(chan struct{}), changed: make(chan struct{}),
	}
	go s.read()
	return s
}

func (s *Splitter) read() {
	defer close(s.done)
	defer close(s.media)
	buf := make([]byte, 4096)
	for {
		n, _, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		b := append([]byte(nil), buf[:n]...)
		ch := s.media
		if IsDTLS(b) {
			ch = s.dtls
		}
		select {
		case ch <- b:
		default: // a full queue drops, as a socket buffer does
		}
	}
}

// Media is every datagram that is not a DTLS record; closed with the socket.
func (s *Splitter) Media() <-chan []byte { return s.media }

// Seal ends the DTLS side: nothing more is written for it and its reads
// fail. The handshake's connection can then be closed without a
// close_notify reaching the server.
func (s *Splitter) Seal() {
	s.mu.Lock()
	if !s.sealed {
		s.sealed = true
		close(s.changed)
		s.changed = make(chan struct{})
	}
	s.mu.Unlock()
}

// DTLSConn is the handshake's view of the socket.
func (s *Splitter) DTLSConn() net.PacketConn { return (*splitDTLS)(s) }

type splitDTLS Splitter

func (c *splitDTLS) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		sealed, deadline, changed := c.sealed, c.deadline, c.changed
		c.mu.Unlock()
		if sealed {
			return 0, nil, net.ErrClosed
		}
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timeout = t.C
		}
		select {
		case b := <-c.dtls:
			return copy(p, b), c.peer, nil
		case <-c.done:
			return 0, nil, net.ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
		}
	}
}

func (c *splitDTLS) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	sealed := c.sealed
	c.mu.Unlock()
	if sealed {
		return len(p), nil
	}
	return c.conn.WriteTo(p, c.peer)
}

func (c *splitDTLS) Close() error { (*Splitter)(c).Seal(); return nil }

func (c *splitDTLS) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *splitDTLS) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *splitDTLS) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *splitDTLS) SetWriteDeadline(time.Time) error { return nil }

// dtlsClientConfig is what the server's acceptance asks for and no more.
func dtlsClientConfig() *dtls.Config {
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled
	return &dtls.Config{
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		InsecureSkipVerify:     true, // a fresh self-signed certificate per handshake; see the header
		FlightInterval:         FlightInterval,
		LoggerFactory:          lf,
	}
}

// clientConfig is dtlsClientConfig; a variable so that a test can run the
// handshake with an offer the server's acceptance would not take.
var clientConfig = dtlsClientConfig

// Handshake runs the DTLS handshake on the splitter's DTLS side and returns
// the wrapper's keys. The DTLS side is sealed on the way out, whatever
// happened: after a handshake only the wrapper speaks on the socket.
func Handshake(ctx context.Context, s *Splitter) (Keys, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	var conn *dtls.Conn
	defer func() {
		s.Seal() // first: the close's alert must not leave
		if conn != nil {
			_ = conn.Close()
		}
	}()
	conn, err := dtls.Client(s.DTLSConn(), s.peer, clientConfig())
	if err != nil {
		return Keys{}, fmt.Errorf("csqtt25: dtls client: %w", err)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return Keys{}, fmt.Errorf("csqtt25: dtls handshake: %w", err)
	}
	// The exporter block means these keys only under this profile; a
	// handshake that agreed on none, or on another, gives nothing to use.
	if profile, ok := conn.SelectedSRTPProtectionProfile(); !ok || profile != dtls.SRTP_AES128_CM_HMAC_SHA1_80 {
		return Keys{}, errors.New("csqtt25: dtls: the handshake did not agree on SRTP_AES128_CM_HMAC_SHA1_80")
	}
	state, ok := conn.ConnectionState()
	if !ok {
		return Keys{}, errors.New("csqtt25: dtls: no connection state after the handshake")
	}
	block, err := state.ExportKeyingMaterial(ExporterLabel, nil, ExporterLen)
	if err != nil {
		return Keys{}, fmt.Errorf("csqtt25: dtls exporter: %w", err)
	}
	keys, ok := KeysFromExporter(block)
	if !ok {
		return Keys{}, errors.New("csqtt25: dtls exporter returned a short block")
	}
	return keys, nil
}
