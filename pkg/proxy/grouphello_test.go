package proxy

import (
	"bytes"
	"testing"
)

// The hello must be built exactly as the server parses it, and — the part that
// actually protects users — must NOT be built at all when the peer belongs to
// someone else.
func TestGroupHelloConstruction(t *testing.T) {
	ours := &Proxy{}
	ours.initGroupHello(Config{})
	if ours.groupHello == nil {
		t.Fatal("no hello built for our own server")
	}
	if len(ours.groupHello) != groupHelloLen {
		t.Fatalf("hello is %d bytes, server accepts exactly %d", len(ours.groupHello), groupHelloLen)
	}
	if !bytes.HasPrefix(ours.groupHello, groupHelloMagic) {
		t.Fatalf("hello does not start with the magic: %x", ours.groupHello)
	}
	if ours.groupHello[0] != 0xff {
		t.Fatal("the first byte must be 0xff — that is what makes an old server " +
			"hand the packet to WireGuard, which drops it, instead of treating " +
			"it as data")
	}

	// Two tunnels must not collide, or the server would put two clients in one
	// group and spray each one's downlink into the other's connections.
	other := &Proxy{}
	other.initGroupHello(Config{})
	if bytes.Equal(ours.groupHello, other.groupHello) {
		t.Fatal("two tunnels produced the same session id")
	}

	// 🚫 Third-party peers: amurcanov's server (WRAP-A) and samosvalishe's
	// (WRAP-S) cannot act on grouping, and we have never read how they treat an
	// unknown sentinel. Sending it there buys nothing and risks something.
	for name, cfg := range map[string]Config{
		"WRAP-A": {UseWrapA: true},
		"WRAP-S": {UseWrapS: true},
		"both":   {UseWrapA: true, UseWrapS: true},
	} {
		p := &Proxy{}
		p.initGroupHello(cfg)
		if p.groupHello != nil {
			t.Fatalf("%s: a hello was built for a third-party server", name)
		}
	}
}

// sendGroupHello must be a no-op rather than a nil-deref when the hello is
// disabled — it runs on the probe path of every conn.
func TestSendGroupHelloIsSafeWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	(&Proxy{}).sendGroupHello(&buf)
	if buf.Len() != 0 {
		t.Fatalf("a disabled hello still wrote %d bytes", buf.Len())
	}

	p := &Proxy{}
	p.initGroupHello(Config{})
	buf.Reset()
	p.sendGroupHello(&buf)
	if !bytes.Equal(buf.Bytes(), p.groupHello) {
		t.Fatalf("sent %x, want %x", buf.Bytes(), p.groupHello)
	}
}

// A hello must never be mistaken for a probe by our own recv path: both start
// with 0xff, and isProbePacket only checks the first four bytes.
func TestHelloIsNotAProbePacket(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	if isProbePacket(p.groupHello) {
		t.Fatal("the group hello is being recognised as a probe pong — the " +
			"zombie detector would treat it as proof the server answered")
	}
}
