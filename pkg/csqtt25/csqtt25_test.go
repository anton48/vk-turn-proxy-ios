package csqtt25

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	mrand "math/rand"
	"net"
	"testing"
	"time"
)

func mustWrapKey(t *testing.T, password string) [KeyLen]byte {
	t.Helper()
	k, err := WrapKey(password)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The wrap key is 2.1.9's: the published vector still holds.
func TestWrapKeyVector(t *testing.T) {
	k := mustWrapKey(t, "test-password")
	if got, want := hex.EncodeToString(k[:]), "aa77380e1203f9e02b705efd192b19020c011619af3d70b03e70c13658e373f4"; got != want {
		t.Fatalf("wrap key = %s, want %s", got, want)
	}
	if _, err := WrapKey(""); err == nil {
		t.Fatal("an empty password gave a key")
	}
}

// The reference's published wire vector for the 2.5 wrapper (their shared
// wire module's GETCONF fixture): the audio shape under the RAW wrap key,
// every random pinned, one byte of padding, no time elapsed.
const getconfFixture = "b06f77881122334410203040bede0002325566775199aa005c468ea9f0329817714cb0d49b032855ae1b18c3ee81bf342bdd58cd166bdf23a16575b0ca29cb53618501b45b3ae4bb1fda630bb39ce45dbf5dde3073f99f87f2da0010b786331f3d88ba24fe8cf3be"

func fixtureWrapper(t *testing.T, key [KeyLen]byte) *Wrapper {
	t.Helper()
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_700_000_000, 0)
	return &Wrapper{
		c: c, mode: ModeAudio, ssrc: 0x10203040, initTS: 0x11223344, initAbs: 0x00556677,
		initSeq: 0x7788, transportSeq: 0x99aa, started: start, rng: mrand.New(mrand.NewSource(1)),
		fixedPad: 1, now: func() time.Time { return start },
	}
}

func TestWrapMatchesThePublishedVector(t *testing.T) {
	plain := []byte("GETCONF:46000|wire-device|wire-password|7|wire-salt|1|27|CSQTT-WIRE-2")
	key := mustWrapKey(t, "wire-password")
	wire, err := fixtureWrapper(t, key).Wrap(nil, plain)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(wire); got != getconfFixture {
		t.Fatalf("wire differs from the published vector\n got %s\nwant %s", got, getconfFixture)
	}
	c, _ := NewCipher(key)
	back, seq, err := c.Unwrap(append([]byte(nil), wire...))
	if err != nil || !bytes.Equal(back, plain) || seq != 0x7788 {
		t.Fatalf("unwrap of the vector: %q seq %#x err %v", back, seq, err)
	}
	// Every single-bit change must fail authentication.
	for i := 0; i < len(wire)*8; i++ {
		bad := append([]byte(nil), wire...)
		bad[i/8] ^= 1 << (i % 8)
		if _, _, err := c.Unwrap(bad); err == nil {
			t.Fatalf("bit %d flipped and the datagram still unwrapped", i)
		}
	}
	other, _ := NewCipher(mustWrapKey(t, "wrong-password"))
	if _, _, err := other.Unwrap(append([]byte(nil), wire...)); err == nil {
		t.Fatal("the vector unwrapped under another password")
	}
}

func TestWrapRoundTripEveryModeAndSize(t *testing.T) {
	keys := WrapKeys(mustWrapKey(t, "round-trip"))
	send, _ := NewCipher(keys.Client)
	recv, _ := NewCipher(keys.Client)
	for _, mode := range []Mode{ModeUnified, ModeAudio, ModeVideo} {
		w, err := NewWrapper(send, mode)
		if err != nil {
			t.Fatal(err)
		}
		var last uint16
		for i, n := range []int{1, 4, 20, 64, 65, 66, 100, 255, 350, 351, 512, 900, 984, 985, 999, 1000, 1024, 1200, 1272, 1280} {
			plain := bytes.Repeat([]byte{byte(n)}, n)
			wire, err := w.Wrap(nil, plain)
			if err != nil {
				t.Fatalf("mode %d size %d: %v", mode, n, err)
			}
			if len(wire) > n+w.Overhead() {
				t.Fatalf("mode %d size %d: wire %d exceeds the stated overhead", mode, n, len(wire))
			}
			if n >= 1000 && len(wire)+4+8+20 > 1350 {
				t.Fatalf("mode %d size %d: %d on the path, above 1350", mode, n, len(wire)+32)
			}
			if !IsRTP(wire) || wire[0] != 0xb0 {
				t.Fatalf("mode %d size %d: not our RTP shape", mode, n)
			}
			back, seq, err := recv.Unwrap(wire)
			if err != nil || !bytes.Equal(back, plain) {
				t.Fatalf("mode %d size %d: round trip failed: %v", mode, n, err)
			}
			if i > 0 && seq != last+1 {
				t.Fatalf("mode %d: sequence %d after %d", mode, seq, last)
			}
			last = seq
		}
	}
}

// The largest packet that travels whole stays under the path ceiling
// whatever the padding draws.
func TestTheLargestWholePacketFitsThePath(t *testing.T) {
	c, _ := NewCipher(WrapKeys(mustWrapKey(t, "ceiling")).Client)
	for _, mode := range []Mode{ModeUnified, ModeAudio} {
		w, _ := NewWrapper(c, mode)
		plain := make([]byte, WholeMax)
		for i := 0; i < 300; i++ {
			wire, err := w.Wrap(nil, plain)
			if err != nil || len(wire)+4+8+20 > 1350 {
				t.Fatalf("mode %d: %d bytes on the path (%v)", mode, len(wire)+32, err)
			}
		}
	}
}

// A small payload is padded up to 100–150 bytes on the wire in the unified
// and audio shapes — the size the reference gives its control strings.
func TestSmallPayloadsArePaddedUp(t *testing.T) {
	c, _ := NewCipher(WrapKeys(mustWrapKey(t, "pad")).Client)
	for _, mode := range []Mode{ModeUnified, ModeAudio} {
		w, _ := NewWrapper(c, mode)
		for i := 0; i < 200; i++ {
			wire, _ := w.Wrap(nil, []byte("READY"))
			if len(wire) < 100 || len(wire) > 150 || wire[1]&0x7f != PTAudio {
				t.Fatalf("mode %d: a 5-byte payload went out as %d bytes, PT %d", mode, len(wire), wire[1]&0x7f)
			}
		}
	}
}

// The WRAP schedule: two different keys, stable for a password, different
// for another. No published vector exists for it — a live server is the
// oracle (tools/csqtt25_client).
func TestWrapKeysAreAStablePair(t *testing.T) {
	a := WrapKeys(mustWrapKey(t, "one"))
	if a.Client == a.Server {
		t.Fatal("the two directions share a key")
	}
	if a != WrapKeys(mustWrapKey(t, "one")) {
		t.Fatal("the schedule is not deterministic")
	}
	if b := WrapKeys(mustWrapKey(t, "two")); a.Client == b.Client || a.Server == b.Server {
		t.Fatal("two passwords share a key")
	}
	raw := mustWrapKey(t, "one")
	if a.Client == raw || a.Server == raw {
		t.Fatal("the schedule returned the wrap key itself")
	}
	if r := RawKeys(raw); r.Client != raw || r.Server != raw {
		t.Fatal("the raw pair is not the wrap key both ways")
	}
	// A datagram for one direction does not open under the other's key.
	send, _ := NewCipher(a.Client)
	other, _ := NewCipher(a.Server)
	w, _ := NewWrapper(send, ModeUnified)
	wire, _ := w.Wrap(nil, []byte("GETCONF:1|p|1|s|1|3"))
	if _, _, err := other.Unwrap(wire); err == nil {
		t.Fatal("the client's datagram opened under the server's key")
	}
}

func TestPRFIsTheTLS12One(t *testing.T) {
	// The TLS 1.2 PRF's public test vector for SHA-256 (the IETF TLS list's
	// «TLS 1.2 PRF test vectors»).
	secret, _ := hex.DecodeString("9bbe436ba940f017b17652849a71db35")
	seed, _ := hex.DecodeString("a0ba9f936cda311827a6f796ffd5198c")
	want := "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
	if got := hex.EncodeToString(prf(secret, "test label", seed, 100)); got != want {
		t.Fatalf("prf = %s", got)
	}
}

func TestFragmentRoundTrip(t *testing.T) {
	pkt := make([]byte, 1500)
	for i := range pkt {
		pkt[i] = byte(i)
	}
	frags := Fragment(101, pkt)
	if len(frags) != 2 || len(frags[0]) != FragHeaderLen+FragMax || len(frags[1]) != FragHeaderLen+228 {
		t.Fatalf("1500 bytes cut into %d fragments", len(frags))
	}
	now := time.Unix(0, 0)
	r := NewReassembler()
	if _, done := r.Push(frags[0], now); done {
		t.Fatal("done after the first fragment")
	}
	if _, done := r.Push(frags[0], now); done {
		t.Fatal("a duplicate completed the packet")
	}
	got, done := r.Push(frags[1], now)
	if !done || !bytes.Equal(got, pkt) {
		t.Fatal("the packet did not come back")
	}

	// The largest packet, last fragment first.
	big := bytes.Repeat([]byte{7}, MaxPacket)
	bf := Fragment(202, big)
	for i := len(bf) - 1; i >= 0; i-- {
		got, done = r.Push(bf[i], now)
		if done != (i == 0) {
			t.Fatalf("fragment %d: done = %v", i, done)
		}
	}
	if !bytes.Equal(got, big) {
		t.Fatal("the largest packet did not come back")
	}
	if Fragment(203, make([]byte, MaxPacket+1)) != nil || Fragment(204, nil) != nil {
		t.Fatal("a packet that cannot travel was fragmented")
	}
}

func TestReassemblyForgetsAStalePacketAndRefusesBadLengths(t *testing.T) {
	r := NewReassembler()
	t0 := time.Unix(0, 0)
	old := Fragment(404, bytes.Repeat([]byte{0x42}, 1500))
	r.Push(old[0], t0)
	fresh := bytes.Repeat([]byte{0x99}, 1500)
	ff := Fragment(404, fresh)
	later := t0.Add(1500 * time.Millisecond)
	if _, done := r.Push(ff[0], later); done {
		t.Fatal("done on the first fragment of the new packet")
	}
	got, done := r.Push(ff[1], later)
	if !done || !bytes.Equal(got, fresh) {
		t.Fatal("the stale half leaked into the new packet")
	}

	bad := append([]byte(nil), old[0]...)
	bad[6], bad[7] = 0x13, 0x88 // total length 5000
	if IsFragment(bad) {
		t.Fatal("a fragment of a 5000-byte packet was accepted")
	}
	// A last fragment cut short must not complete the packet its first half began.
	half := Fragment(405, bytes.Repeat([]byte{0x17}, 1500))
	r.Push(half[0], later)
	if _, done := r.Push(half[1][:FragHeaderLen+10], later); done {
		t.Fatal("a short last fragment completed a packet")
	}
	// Eight bytes that are a well-formed fragment header in everything but
	// the magic: index 0 of 1, 20 bytes in all.
	if IsFragment([]byte{0x45, 0, 1, 0, 0, 0, 0, 20}) {
		t.Fatal("an IP header read as a fragment")
	}
}

func TestControlStrings(t *testing.T) {
	if got := ConfigRequest("9000", "pass1234567890ab", 7, "salt", 4, 0); got != "GETCONF:9000|pass1234567890ab|7|salt|4|" {
		t.Fatal(got)
	}
	if got := ConfigRequest("9000", "pass1234567890ab", 7, "salt", 4, 36); got != "GETCONF:9000|pass1234567890ab|7|salt|4|36" {
		t.Fatal(got)
	}
	if got := WorkersRequest("pass123", 25); got != "GETWORKERS:pass123|25" {
		t.Fatal(got)
	}
	if got := DisconnectRequest("pass123", "salt99"); got != "DISCONNECT:pass123|salt99" {
		t.Fatal(got)
	}
	c, err := ParseConfigResponse([]byte("TUNCONF:198.51.100.2:192.0.2.53:45000:stream-v1:workers=20"))
	if err != nil || c.TunnelIP != "198.51.100.2" || c.DNS != "192.0.2.53" || c.Port != "45000" || c.Stream != "stream-v1" || c.Workers != 20 {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := ParseConfigResponse([]byte("TUNCONF:198.51.100.2:192.0.2.53")); err != nil || c.Workers != 0 || c.Stream != "" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := ParseConfigResponse([]byte("NOCONF")); err != ErrNoConfig {
		t.Fatal(err)
	}
	for reason, fatal := range map[string]bool{"wrong_password": true, "expired": true, "deactivated": true, "protocol_mismatch": true,
		"invalid_epoch": false, "invalid_worker": false, "invalid_worker_count": false, "server_busy": false, "not_owner": false} {
		_, err := ParseConfigResponse([]byte("DENIED:" + reason))
		d, ok := err.(*DeniedError)
		if !ok || d.Reason != reason || d.Fatal() != fatal {
			t.Fatalf("DENIED:%s → %v", reason, err)
		}
	}
	for in, want := range map[string][2]int{"TUNWORKERS:20:20": {20, 20}, "TUNWORKERS:44:0": {44, 0}, "WORKERS:15": {15, 15}} {
		a, l, ok := ParseWorkers([]byte(in))
		if !ok || a != want[0] || l != want[1] {
			t.Fatalf("%s → %d %d %v", in, a, l, ok)
		}
	}
	if _, _, ok := ParseWorkers([]byte("TUNCONF:192.0.2.4")); ok {
		t.Fatal("a TUNCONF parsed as a worker count")
	}
	for _, p := range [][]byte{[]byte("TUNCONF:a:b"), []byte("NOCONF"), []byte("DENIED:expired"), []byte("READY_OK"), []byte("OK:disconnected"),
		[]byte("TUNWORKERS:20:20"), []byte("WORKERS:20"), []byte("ROUTING:START:3"), panelRestartNotice, streamRepairPrefix, streamAlivePrefix, pathEchoPrefix} {
		if !IsControl(p) || ControlName(p) == "" {
			t.Fatalf("%q is not read as control", p)
		}
	}
	if IsControl([]byte{0x45, 0, 0, 20}) {
		t.Fatal("an IP packet read as control")
	}
	if !IsIdleKeepalive(IdleKeepalive) || !IsIdleKeepalive(bytes.Repeat([]byte{0xff}, 16)) || IsIdleKeepalive([]byte{0xff, 1, 2}) || IsIdleKeepalive(nil) {
		t.Fatal("the keepalive rule")
	}
}

func TestLinkRoundTripAndThePlainFormIsNotOurs(t *testing.T) {
	in := Link{Host: "203.0.113.7", Port: 46000, Password: "secret-pass", Hashes: []string{"abcdefghijklmnop", "qrstuvwxyz012345"}}
	raw, err := EncodeLink(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeLink(raw)
	if err != nil || out.Host != in.Host || out.Port != in.Port || out.Password != in.Password || len(out.Hashes) != 2 || out.Hashes[1] != in.Hashes[1] {
		t.Fatalf("%+v %v", out, err)
	}
	again, _ := EncodeLink(in)
	if again != raw {
		t.Fatal("a link is not stable")
	}
	tok, _ := EncodeLink(Link{Host: "vps.example", Port: 1, Password: "p", Token: "vk1.a.token"})
	if l, err := DecodeLink(tok); err != nil || l.Token != "vk1.a.token" || len(l.Hashes) != 0 {
		t.Fatalf("%+v %v", l, err)
	}
	for _, plain := range []string{
		"csqtt://connect?v=2&host=203.0.113.7&peer=46000&password=secret",
		"csqtt://secret@203.0.113.7:46000",
		"https://example.test/",
		"csqtt://AAAA",
	} {
		if IsEncryptedLink(plain) {
			t.Fatalf("%q read as a 2.5 link", plain)
		}
	}
	damaged := []byte(raw)
	damaged[len(damaged)-3] ^= 1
	if IsEncryptedLink(string(damaged)) {
		t.Fatal("a damaged link decoded")
	}
}

// The two key schedules against their known answers (kat_test.go).
func TestKeySchedulesKnownAnswers(t *testing.T) {
	w := WrapKeys(mustWrapKey(t, "wire-password"))
	if hex.EncodeToString(w.Client[:]) != katWrapClient || hex.EncodeToString(w.Server[:]) != katWrapServer {
		t.Fatal("the WRAP schedule no longer gives the keys the live server accepted")
	}
	block := make([]byte, ExporterLen)
	for i := range block {
		block[i] = byte(i)
	}
	e, ok := KeysFromExporter(block)
	if !ok || hex.EncodeToString(e.Client[:]) != katExporterClient || hex.EncodeToString(e.Server[:]) != katExporterServer {
		t.Fatal("the exporter block is no longer cut and expanded as the live server does")
	}
	// The first half of a direction's key is its master key, as it stands in the block.
	if !bytes.Equal(e.Client[:16], block[0:16]) || !bytes.Equal(e.Server[:16], block[16:32]) {
		t.Fatal("a direction's AES key is not its master key")
	}
}

// sealBody makes an authentic datagram around an arbitrary body — what only
// the key's holder can send.
func sealBody(c *Cipher, body []byte) []byte { return sealBodyExt(c, body, 2) }

// sealBodyExt is sealBody with a header extension of the given length in
// 32-bit words (ours is two).
func sealBodyExt(c *Cipher, body []byte, words int) []byte {
	hdrLen := 16 + words*4
	wire := make([]byte, hdrLen+len(body)+tagLen)
	wire[0], wire[1] = 0xb0, PTAudio
	binary.BigEndian.PutUint16(wire[2:4], 7)
	binary.BigEndian.PutUint32(wire[4:8], 9)
	binary.BigEndian.PutUint32(wire[8:12], 11)
	binary.BigEndian.PutUint16(wire[12:14], 0xbede)
	binary.BigEndian.PutUint16(wire[14:16], uint16(words))
	copy(wire[hdrLen:], body)
	iv := srtpIV(11, 7, 9)
	cipher.NewCTR(c.block, iv[:]).XORKeyStream(wire[hdrLen:hdrLen+len(body)], wire[hdrLen:hdrLen+len(body)])
	mac := hmac.New(sha1.New, c.macKey)
	mac.Write(wire[:hdrLen+len(body)])
	copy(wire[hdrLen+len(body):], mac.Sum(nil)[:tagLen])
	return wire
}

// An authentic datagram whose padding length lies is refused, not sliced.
func TestALyingPaddingLengthIsRefused(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a lying padding length was sliced: %v", r)
		}
	}()
	c, _ := NewCipher(WrapKeys(mustWrapKey(t, "pad-bounds")).Client)
	for _, body := range [][]byte{
		{1, 2, 3, 200},                          // claims 200 bytes of padding in a 4-byte body
		{1, 2, 3, 0},                            // claims none, with the padding bit set
		append(bytes.Repeat([]byte{9}, 40), 42), // one more than the body holds
	} {
		if _, _, err := c.Unwrap(sealBody(c, body)); err == nil {
			t.Fatalf("a body of %d bytes ending in %d unwrapped", len(body), body[len(body)-1])
		}
	}
	// The honest neighbours of those cases do unwrap.
	if p, _, err := c.Unwrap(sealBody(c, []byte{1, 2, 3, 4})); err != nil || len(p) != 0 {
		t.Fatalf("padding that fills the body: %v %d", err, len(p))
	}
	if p, _, err := c.Unwrap(sealBody(c, []byte{1, 2, 3, 1})); err != nil || !bytes.Equal(p, []byte{1, 2, 3}) {
		t.Fatalf("one byte of padding: %v", err)
	}
}

// sealLink makes a 2.5 link around an arbitrary plaintext.
func sealLink(t *testing.T, plain string) string {
	t.Helper()
	g, _, err := linkAEAD()
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{3}, 12)
	return "csqtt://" + base64.RawURLEncoding.EncodeToString(append(iv, g.Seal(nil, iv, []byte(plain), nil)...))
}

// The reference app's own published link vector (its unit test's «Rust»
// link): it decodes here, to an address and its port.
func TestTheReferencesPublishedLinkDecodes(t *testing.T) {
	const vector = "csqtt://GNANVH0fhD6MisDFiWP_P0Bm_FHr-frawgfwur3Zx4ipjJx8gk-M6ZZbnDr_2clwPmzO-QS8AkiHLaMXyYO1RHyPeehXPqTc6jJi_iw72fRQJ9AR918ne5XsBRg"
	l, err := DecodeLink(vector)
	if err != nil {
		t.Fatalf("the published vector: %v", err)
	}
	if l.Port != 46000 || net.ParseIP(l.Host) == nil {
		t.Fatalf("the published vector decoded to port %d and a host that is not an address", l.Port)
	}
}

func TestALinkOfAnotherShapeIsRefusedAfterItDecrypts(t *testing.T) {
	if _, err := DecodeLink(sealLink(t, "connect?v=2&host=vps.example&peer=46000&password=p")); err != nil {
		t.Fatalf("the control: %v", err)
	}
	for _, plain := range []string{
		"connect?v=3&host=vps.example&peer=46000&password=p",
		"connect?host=vps.example&peer=46000&password=p",
		"connect?v=2&peer=46000&password=p",
		"connect?v=2&host=vps.example&peer=0&password=p",
		"connect?v=2&host=vps.example&peer=70000&password=p",
		"connect?v=2&host=vps.example&password=p",
	} {
		if _, err := DecodeLink(sealLink(t, plain)); err == nil {
			t.Fatalf("%q was taken", plain)
		}
	}
	// A password with the characters a query string would mangle survives.
	raw, _ := EncodeLink(Link{Host: "vps.example", Port: 7, Password: "a+b c%2Fd"})
	if l, err := DecodeLink(raw); err != nil || l.Password != "a+b c%2Fd" {
		t.Fatalf("the password came back as %q (%v)", l.Password, err)
	}
}

// The header's length is read off the datagram (the extension's own length
// field), not assumed to be ours.
func TestUnwrapTakesTheHeaderLengthFromTheDatagram(t *testing.T) {
	c, _ := NewCipher(WrapKeys(mustWrapKey(t, "ext")).Client)
	for _, words := range []int{0, 1, 2, 3, 5} {
		p, seq, err := c.Unwrap(sealBodyExt(c, []byte{0xa, 0xb, 0xc, 1}, words))
		if err != nil || !bytes.Equal(p, []byte{0xa, 0xb, 0xc}) || seq != 7 {
			t.Fatalf("an extension of %d words: %x %v", words, p, err)
		}
	}
}

func TestIsRTP(t *testing.T) {
	hdr := func(first, pt byte) []byte { b := make([]byte, 40); b[0], b[1] = first, pt; return b }
	for _, pt := range []byte{PTAudio, PTVideo, ptLegacy, PTVideo | 0x80} {
		if !IsRTP(hdr(0xb0, pt)) {
			t.Fatalf("payload type %d refused", pt)
		}
	}
	if IsRTP(hdr(0xb0, 0)) || IsRTP(hdr(0xb0, 8)) || IsRTP(hdr(0xb0, 110)) {
		t.Fatal("a payload type that is not ours was taken")
	}
	if IsRTP(hdr(0x30, PTAudio)) || IsRTP(hdr(22, PTAudio)) || IsRTP(hdr(0xb0, PTAudio)[:12]) || IsRTP(nil) {
		t.Fatal("something that is not RTP version 2 was taken")
	}
	c, _ := NewCipher(WrapKeys(mustWrapKey(t, "rtp")).Client)
	foreign := sealBody(c, []byte{1, 2, 3, 1})
	foreign[1] = 8
	if _, _, err := c.Unwrap(foreign); err == nil {
		t.Fatal("a foreign payload type unwrapped")
	}
}

// Two packets in flight at once come back whole, each under its own id.
func TestInterleavedPacketsAreKeptApartByTheirIDs(t *testing.T) {
	a := bytes.Repeat([]byte{0xaa}, 1500)
	b := bytes.Repeat([]byte{0xbb}, 1500)
	fa, fb := Fragment(1, a), Fragment(2, b)
	r := NewReassembler()
	now := time.Unix(0, 0)
	r.Push(fa[0], now)
	r.Push(fb[0], now)
	gotA, doneA := r.Push(fa[1], now)
	gotB, doneB := r.Push(fb[1], now)
	if !doneA || !doneB || !bytes.Equal(gotA, a) || !bytes.Equal(gotB, b) {
		t.Fatalf("interleaved packets: done %v %v", doneA, doneB)
	}
	if binary.BigEndian.Uint16(fa[0][4:6]) != 1 || binary.BigEndian.Uint16(fb[1][4:6]) != 2 {
		t.Fatal("a fragment does not carry its packet's id")
	}
}
