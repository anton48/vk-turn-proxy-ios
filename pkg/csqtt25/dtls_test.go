package csqtt25

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
)

// A stand-in for the 2.5 server's DTLS side, as narrow as its acceptance: a
// self-signed ECDSA P-256 certificate, one cipher suite, one SRTP profile,
// extended master secret required, no client certificate asked.
func strictServerConfig(t *testing.T) *dtls.Config {
	t.Helper()
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled
	return &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		ClientAuth:             dtls.NoClientCert,
		LoggerFactory:          lf,
	}
}

func udpPair(t *testing.T) (a, b *net.UDPConn) {
	t.Helper()
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// The handshake on a shared socket: both ends reach the SAME pair of keys
// from the exporter, the client's datagram opens under the client key on the
// far side and the answer under the server key here — and the wrapper's
// datagrams travel on the very socket the handshake used.
func TestHandshakeYieldsTheWrappersKeysOnASharedSocket(t *testing.T) {
	srvSock, cliSock := udpPair(t)
	srvSplit := NewSplitter(srvSock, cliSock.LocalAddr())
	cliSplit := NewSplitter(cliSock, srvSock.LocalAddr())

	type srvResult struct {
		keys Keys
		err  error
	}
	srvDone := make(chan srvResult, 1)
	go func() {
		conn, err := dtls.Server(srvSplit.DTLSConn(), cliSock.LocalAddr(), strictServerConfig(t))
		if err != nil {
			srvDone <- srvResult{err: err}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := conn.HandshakeContext(ctx); err != nil {
			srvDone <- srvResult{err: err}
			return
		}
		state, _ := conn.ConnectionState()
		// The label and the length as RFC 5764 spells them, not as this
		// package's constants do: the far side must agree with the standard.
		block, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, 60)
		keys, _ := KeysFromExporter(block)
		srvDone <- srvResult{keys: keys, err: err}
	}()

	cliKeys, err := Handshake(context.Background(), cliSplit)
	if err != nil {
		t.Fatalf("the client's handshake: %v", err)
	}
	srv := <-srvDone
	if srv.err != nil {
		t.Fatalf("the server's handshake: %v", srv.err)
	}
	if cliKeys != srv.keys {
		t.Fatal("the two ends derived different keys from one handshake")
	}
	if cliKeys.Client == cliKeys.Server {
		t.Fatal("the two directions share a key")
	}

	// Client → server under the client key.
	send, _ := NewCipher(cliKeys.Client)
	w, _ := NewWrapper(send, ModeUnified)
	plain := []byte("GETCONF:9000|p|7|salt|1|18")
	wire, _ := w.Wrap(nil, plain)
	if _, err := cliSock.WriteTo(wire, srvSock.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-srvSplit.Media():
		open, _ := NewCipher(srv.keys.Client)
		back, _, err := open.Unwrap(got)
		if err != nil || !bytes.Equal(back, plain) {
			t.Fatalf("the server did not open the client's datagram: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the wrapper's datagram did not reach the far side's media queue")
	}

	// Server → client under the server key.
	ssend, _ := NewCipher(srv.keys.Server)
	sw, _ := NewWrapper(ssend, ModeUnified)
	answer := []byte("TUNCONF:198.51.100.2:192.0.2.53:9000:stream-v1:workers=18")
	swire, _ := sw.Wrap(nil, answer)
	if _, err := srvSock.WriteTo(swire, cliSock.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-cliSplit.Media():
		open, _ := NewCipher(cliKeys.Server)
		back, _, err := open.Unwrap(got)
		if err != nil || !bytes.Equal(back, answer) {
			t.Fatalf("the client did not open the server's datagram: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the answer did not reach the client's media queue")
	}
}

// recordingConn notes the first byte of every datagram written through it.
type recordingConn struct {
	net.PacketConn
	mu    sync.Mutex
	first []byte
}

func (r *recordingConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if len(p) > 0 {
		r.mu.Lock()
		r.first = append(r.first, p[0])
		r.mu.Unlock()
	}
	return r.PacketConn.WriteTo(p, a)
}

func (r *recordingConn) written() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.first...)
}

// After a handshake the DTLS side is sealed: closing the handshake's
// connection puts no close_notify on the socket (the server would read an
// alert as a failure), and nothing written for DTLS afterwards leaves.
func TestNothingOfDTLSLeavesAfterTheHandshake(t *testing.T) {
	srvSock, cliUDP := udpPair(t)
	cliSock := &recordingConn{PacketConn: cliUDP}
	srvSplit := NewSplitter(srvSock, cliUDP.LocalAddr())
	cliSplit := NewSplitter(cliSock, srvSock.LocalAddr())
	go func() {
		conn, err := dtls.Server(srvSplit.DTLSConn(), cliUDP.LocalAddr(), strictServerConfig(t))
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = conn.HandshakeContext(ctx)
		}
	}()
	if _, err := Handshake(context.Background(), cliSplit); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // a late write of the closed connection would land here
	sent := cliSock.written()
	if len(sent) == 0 {
		t.Fatal("the recorder saw no handshake at all")
	}
	for i, b := range sent {
		if b == 21 {
			t.Fatalf("datagram %d of %d written by the handshake is a DTLS alert", i+1, len(sent))
		}
	}
	if n, err := cliSplit.DTLSConn().WriteTo([]byte{22, 0xfe, 0xfd, 0, 1}, nil); err != nil || n != 5 {
		t.Fatalf("a write on the sealed side: %d %v", n, err)
	}
	if after := cliSock.written(); len(after) != len(sent) {
		t.Fatalf("%d datagram(s) left through the sealed side", len(after)-len(sent))
	}
	// A read on the sealed side ends at once and says the side is closed (the
	// deadline is only this test's own bound).
	_ = cliSplit.DTLSConn().SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := cliSplit.DTLSConn().ReadFrom(make([]byte, 16)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a read on the sealed side: %v", err)
	}
}

// The handshake is bounded by itself: a caller that sets no deadline still
// gets its socket back. (The bound is the reference's eight seconds; the
// test shortens it.)
func TestTheHandshakeIsBoundedWithoutTheCallersDeadline(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = 300 * time.Millisecond
	defer func() { handshakeTimeout = old }()
	srvSock, cliSock := udpPair(t)
	cliSplit := NewSplitter(cliSock, srvSock.LocalAddr())
	done := make(chan error, 1)
	go func() {
		_, err := Handshake(context.Background(), cliSplit)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a handshake with a silent peer succeeded")
		}
	case <-time.After(3 * time.Second):
		cliSock.Close() // let the goroutine go
		t.Fatal("the handshake outlived its own bound")
	}
}

// A server that will not do the extended master secret is refused: the keys
// would hang on a master secret an attacker in the middle can line up.
func TestAServerWithoutExtendedMasterSecretIsRefused(t *testing.T) {
	srvSock, cliSock := udpPair(t)
	srvSplit := NewSplitter(srvSock, cliSock.LocalAddr())
	cliSplit := NewSplitter(cliSock, srvSock.LocalAddr())
	cfg := strictServerConfig(t)
	cfg.ExtendedMasterSecret = dtls.DisableExtendedMasterSecret
	go func() {
		conn, err := dtls.Server(srvSplit.DTLSConn(), cliSock.LocalAddr(), cfg)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = conn.HandshakeContext(ctx)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := Handshake(ctx, cliSplit); err == nil {
		t.Fatal("a handshake without the extended master secret gave keys")
	}
}

// A server that offers nothing the acceptance names is refused in time, and
// the socket is left usable for the wrapper (the reference's auto mode goes
// on with password-derived keys).
func TestAFailedHandshakeLeavesTheSocketToTheWrapper(t *testing.T) {
	srvSock, cliSock := udpPair(t)
	cliSplit := NewSplitter(cliSock, srvSock.LocalAddr())
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	began := time.Now()
	if _, err := Handshake(ctx, cliSplit); err == nil {
		t.Fatal("a handshake with a silent peer succeeded")
	}
	if d := time.Since(began); d > 3*time.Second {
		t.Fatalf("the failed handshake took %s", d)
	}
	send, _ := NewCipher(WrapKeys(mustWrapKey(t, "after")).Server)
	w, _ := NewWrapper(send, ModeUnified)
	wire, _ := w.Wrap(nil, []byte("READY_OK"))
	if _, err := srvSock.WriteTo(wire, cliSock.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-cliSplit.Media():
		if !IsRTP(got) {
			t.Fatal("the media queue returned something else")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the socket no longer delivers to the wrapper after a failed handshake")
	}
}

func TestIsDTLS(t *testing.T) {
	for b, want := range map[byte]bool{19: false, 20: true, 22: true, 63: true, 64: false, 0x80: false, 0xb0: false, 0: false} {
		if IsDTLS([]byte{b, 0, 0}) != want {
			t.Fatalf("first byte %d", b)
		}
	}
	if IsDTLS(nil) {
		t.Fatal("an empty datagram")
	}
	if _, ok := KeysFromExporter(make([]byte, 59)); ok {
		t.Fatal("a short exporter block gave keys")
	}
}

// A handshake that agreed on no SRTP profile gives no keys: without the
// profile the exporter's block is not the wrapper's. (pion completes such a
// handshake when the client offers no profile; the offer is this test's.)
func TestAHandshakeWithoutTheSRTPProfileIsRefused(t *testing.T) {
	old := clientConfig
	clientConfig = func() *dtls.Config {
		cfg := dtlsClientConfig()
		cfg.SRTPProtectionProfiles = nil
		return cfg
	}
	defer func() { clientConfig = old }()
	srvSock, cliSock := udpPair(t)
	srvSplit := NewSplitter(srvSock, cliSock.LocalAddr())
	cliSplit := NewSplitter(cliSock, srvSock.LocalAddr())
	srvDone := make(chan error, 1)
	go func() {
		conn, err := dtls.Server(srvSplit.DTLSConn(), cliSock.LocalAddr(), strictServerConfig(t))
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = conn.HandshakeContext(ctx)
		}
		srvDone <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Handshake(ctx, cliSplit)
	if srvErr := <-srvDone; srvErr != nil {
		t.Fatalf("the fixture: the far side did not complete the handshake (%v) — the refusal below would be pion's, not ours", srvErr)
	}
	if err == nil {
		t.Fatal("a handshake that agreed on no SRTP profile gave keys")
	}
}
