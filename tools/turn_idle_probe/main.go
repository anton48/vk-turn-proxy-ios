// SPDX-License-Identifier: MIT

// turn_idle_probe answers one question about the VK TURN relay: how long does
// it keep the TCP connection of an allocation whose client has gone SILENT?
//
// Why: an iOS extension is frozen for a minute at a time, now and then for
// minutes. While it is frozen nothing is sent — no keepalive, no TURN Refresh —
// and once, after a 208-second freeze, a client found all fifty of its relay
// connections dropped by the far side although every TURN lifetime was still
// running (the allocations were 400–430 s old of 600). Whether the RELAY does
// that to a silent connection, or something on that user's path did, cannot be
// read from a phone log; it can be measured from a host with a plain path.
//
// How: TURN over TCP spoken by hand (pion/stun for the messages only). pion's
// TURN client refreshes on its own timers, and silence is the whole point:
// each arm allocates, optionally installs a permission and a channel and sends
// one datagram (what a real connection has done before it goes quiet), then
// sends NOTHING for its silence while a read waits for the far side's FIN or
// RST, and finally asks with one Refresh whether the allocation still lives.
//
// Two arms keep the run honest: a CONTROL that refreshes every 25 s for the
// longest silence (the relay and the credential were fine all along), and a
// silence LONGER than the allocation's lifetime, which must come back dead —
// an "alive" verdict proves nothing without an arm that would have been
// refused.
//
// Nothing secret is printed: not the link, not the credential, and of the
// relay only its first two octets.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"github.com/pion/stun/v3"
)

const (
	requestTimeout = 5 * time.Second
	controlEvery   = 25 * time.Second
	firstChannel   = 0x4000
)

type frameKind int

const (
	frameSTUN frameKind = iota
	frameChannelData
)

// readFrame reads one frame of a TURN-over-TCP stream: a STUN message, or a
// ChannelData frame — which on a stream is PADDED to a multiple of four bytes
// (RFC 8656 §12.5); skipping the padding wrongly desynchronises everything
// after it.
func readFrame(r io.Reader) (frameKind, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4]))
	switch hdr[0] & 0xC0 {
	case 0x40: // channel numbers 0x4000–0x7FFF
		body := make([]byte, (n+3)&^3)
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
		return frameChannelData, body[:n], nil
	case 0x00: // a STUN message: n is the length after the 20-byte header
		msg := make([]byte, 20+n)
		copy(msg, hdr[:])
		if _, err := io.ReadFull(r, msg[4:]); err != nil {
			return 0, nil, err
		}
		return frameSTUN, msg, nil
	}
	return 0, nil, fmt.Errorf("neither STUN nor ChannelData: first byte %#02x", hdr[0])
}

type xorPeer struct{ addr *net.UDPAddr }

func (p xorPeer) AddTo(m *stun.Message) error {
	return stun.XORMappedAddress{IP: p.addr.IP, Port: p.addr.Port}.AddToAs(m, stun.AttrXORPeerAddress)
}

func lifetimeAttr(d time.Duration) stun.RawAttribute {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, uint32(d/time.Second))
	return stun.RawAttribute{Type: stun.AttrLifetime, Value: v}
}

// session is one TURN allocation over one TCP connection.
type session struct {
	conn        net.Conn
	user, pass  string
	realm       string
	nonce       string
	strayFrames int // frames that answered nothing we asked
}

var errStaleNonce = errors.New("stale nonce")

// roundTrip sends one request and waits for ITS answer. auth adds the
// long-term credential; a 438 refreshes the nonce and is retried once by the
// caller through do().
func (s *session) roundTrip(method stun.Method, auth bool, attrs ...stun.Setter) (*stun.Message, int, error) {
	setters := []stun.Setter{stun.TransactionID, stun.NewType(method, stun.ClassRequest)}
	setters = append(setters, attrs...)
	if auth {
		setters = append(setters, stun.NewUsername(s.user), stun.NewRealm(s.realm), stun.NewNonce(s.nonce),
			stun.NewLongTermIntegrity(s.user, s.realm, s.pass))
	}
	setters = append(setters, stun.Fingerprint)
	req, err := stun.Build(setters...)
	if err != nil {
		return nil, 0, err
	}
	_ = s.conn.SetDeadline(time.Now().Add(requestTimeout))
	defer s.conn.SetDeadline(time.Time{})
	if _, err := s.conn.Write(req.Raw); err != nil {
		return nil, 0, fmt.Errorf("write: %w", err)
	}
	for {
		kind, raw, err := readFrame(s.conn)
		if err != nil {
			return nil, 0, fmt.Errorf("read: %w", err)
		}
		if kind != frameSTUN {
			s.strayFrames++
			continue
		}
		res := &stun.Message{Raw: raw}
		if err := res.Decode(); err != nil {
			return nil, 0, fmt.Errorf("decode: %w", err)
		}
		if res.TransactionID != req.TransactionID {
			s.strayFrames++
			continue
		}
		if res.Type.Class == stun.ClassErrorResponse {
			var ec stun.ErrorCodeAttribute
			_ = ec.GetFrom(res)
			var realm stun.Realm
			var nonce stun.Nonce
			if realm.GetFrom(res) == nil {
				s.realm = realm.String()
			}
			if nonce.GetFrom(res) == nil {
				s.nonce = nonce.String()
			}
			if ec.Code == stun.CodeStaleNonce {
				return res, int(ec.Code), errStaleNonce
			}
			return res, int(ec.Code), nil
		}
		return res, 0, nil
	}
}

// do is roundTrip with the one retry a stale nonce is owed.
func (s *session) do(method stun.Method, attrs ...stun.Setter) (*stun.Message, int, error) {
	res, code, err := s.roundTrip(method, true, attrs...)
	if errors.Is(err, errStaleNonce) {
		res, code, err = s.roundTrip(method, true, attrs...)
	}
	return res, code, err
}

func lifetimeOf(m *stun.Message) time.Duration {
	if v, err := m.Get(stun.AttrLifetime); err == nil && len(v) == 4 {
		return time.Duration(binary.BigEndian.Uint32(v)) * time.Second
	}
	return 0
}

// allocate runs the 401 challenge and the authenticated Allocate.
func (s *session) allocate() (time.Duration, error) {
	udp := stun.RawAttribute{Type: stun.AttrRequestedTransport, Value: []byte{17, 0, 0, 0}}
	_, code, err := s.roundTrip(stun.MethodAllocate, false, udp)
	if err != nil {
		return 0, err
	}
	if code != int(stun.CodeUnauthorized) || s.realm == "" || s.nonce == "" {
		return 0, fmt.Errorf("the unauthenticated Allocate was answered with code %d, want a 401 carrying a realm and a nonce", code)
	}
	res, code, err := s.do(stun.MethodAllocate, udp)
	if err != nil {
		return 0, err
	}
	if code != 0 {
		return 0, fmt.Errorf("Allocate refused: error %d", code)
	}
	return lifetimeOf(res), nil
}

// warmUp does what a real connection has done before it goes quiet: a
// permission, a channel, one datagram to the peer.
func (s *session) warmUp(peer *net.UDPAddr) error {
	if _, code, err := s.do(stun.MethodCreatePermission, xorPeer{peer}); err != nil || code != 0 {
		return fmt.Errorf("CreatePermission: code %d, %v", code, err)
	}
	ch := stun.RawAttribute{Type: stun.AttrChannelNumber, Value: []byte{firstChannel >> 8, firstChannel & 0xff, 0, 0}}
	if _, code, err := s.do(stun.MethodChannelBind, ch, xorPeer{peer}); err != nil || code != 0 {
		return fmt.Errorf("ChannelBind: code %d, %v", code, err)
	}
	payload := []byte("idle-probe\x00\x00") // 12 bytes: already a multiple of four
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], firstChannel)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
	copy(frame[4:], payload)
	_ = s.conn.SetWriteDeadline(time.Now().Add(requestTimeout))
	_, err := s.conn.Write(frame)
	_ = s.conn.SetWriteDeadline(time.Time{})
	return err
}

// stayQuiet sends nothing for d and listens: the far side's FIN or RST is
// reported with the moment it came. Unasked frames are counted, not answered.
func (s *session) stayQuiet(d time.Duration) (closedAfter time.Duration, how string) {
	start := time.Now()
	_ = s.conn.SetReadDeadline(start.Add(d))
	defer s.conn.SetReadDeadline(time.Time{})
	for {
		_, _, err := readFrame(s.conn)
		if err == nil {
			s.strayFrames++
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return 0, ""
		}
		if errors.Is(err, io.EOF) {
			return time.Since(start), "FIN (the far side closed)"
		}
		return time.Since(start), err.Error()
	}
}

type result struct {
	name      string
	silence   time.Duration
	allocated time.Duration // the lifetime the relay granted
	verdict   string
	detail    string
}

type arm struct {
	name    string
	silence time.Duration
	control bool // refresh every controlEvery instead of staying silent
}

func runArm(a arm, relay string, creds *proxy.TURNCreds, peer *net.UDPAddr) result {
	res := result{name: a.name, silence: a.silence}
	conn, err := (&net.Dialer{Timeout: requestTimeout}).Dial("tcp4", relay)
	if err != nil {
		res.verdict, res.detail = "NOT RUN", "dial: "+err.Error()
		return res
	}
	defer conn.Close()
	s := &session{conn: conn, user: creds.Username, pass: creds.Password}
	t0 := time.Now()
	if res.allocated, err = s.allocate(); err != nil {
		res.verdict, res.detail = "NOT RUN", err.Error()
		return res
	}
	if peer != nil {
		if err := s.warmUp(peer); err != nil {
			res.verdict, res.detail = "NOT RUN", err.Error()
			return res
		}
	}
	log.Printf("[%s] allocated in %s, lifetime %s%s — now %s", a.name, time.Since(t0).Round(time.Millisecond), res.allocated,
		map[bool]string{true: ", permission + channel + one datagram", false: ""}[peer != nil],
		map[bool]string{true: fmt.Sprintf("a Refresh every %s for %s", controlEvery, a.silence), false: fmt.Sprintf("SILENT for %s", a.silence)}[a.control])

	if a.control {
		refreshes := 0
		for end := time.Now().Add(a.silence); time.Now().Before(end); {
			if closed, how := s.stayQuiet(controlEvery); how != "" {
				res.verdict, res.detail = "DEAD", fmt.Sprintf("closed %s into a quiet stretch after %d refreshes: %s", closed.Round(time.Second), refreshes, how)
				return res
			}
			if _, code, err := s.do(stun.MethodRefresh, lifetimeAttr(10*time.Minute)); err != nil || code != 0 {
				res.verdict, res.detail = "DEAD", fmt.Sprintf("refresh %d: code %d, %v", refreshes+1, code, err)
				return res
			}
			refreshes++
		}
		res.verdict, res.detail = "ALIVE", fmt.Sprintf("%d refreshes answered", refreshes)
	} else {
		if closed, how := s.stayQuiet(a.silence); how != "" {
			res.verdict, res.detail = "DEAD", fmt.Sprintf("the connection ended %s into the silence: %s", closed.Round(100*time.Millisecond), how)
			return res
		}
		t1 := time.Now()
		r, code, err := s.do(stun.MethodRefresh, lifetimeAttr(10*time.Minute))
		switch {
		case err != nil:
			res.verdict, res.detail = "DEAD", fmt.Sprintf("no FIN/RST during the silence, but the Refresh after it failed: %v", err)
			return res
		case code != 0:
			res.verdict, res.detail = "ALLOCATION GONE", fmt.Sprintf("the TCP connection answers, the Refresh is refused with error %d", code)
			return res
		}
		res.verdict, res.detail = "ALIVE", fmt.Sprintf("no FIN/RST during the silence; Refresh answered in %s, lifetime %s", time.Since(t1).Round(time.Millisecond), lifetimeOf(r))
	}
	if s.strayFrames > 0 {
		res.detail += fmt.Sprintf("; %d unasked frame(s) from the relay", s.strayFrames)
	}
	_, _, _ = s.do(stun.MethodRefresh, lifetimeAttr(0)) // give the allocation back
	return res
}

func maskHost(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "?"
	}
	if p := strings.Split(host, "."); len(p) == 4 {
		return p[0] + "." + p[1] + ".x.x:" + port
	}
	return "host:" + port
}

func main() {
	linkFile := flag.String("vk-link-file", "", "file holding the VK call link (kept out of the command line and of this tool's output)")
	silences := flag.String("silence", "70s,130s,220s,400s,650s", "comma-separated silences; include one LONGER than the allocation lifetime — it must come back dead")
	peerFlag := flag.String("peer", "", "optional ip:port: install a permission and a channel for it and send one datagram before going silent")
	noControl := flag.Bool("no-control", false, "skip the control arm (a Refresh every 25 s for the longest silence)")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	raw, err := os.ReadFile(*linkFile)
	if err != nil {
		log.Fatalf("-vk-link-file: %v", err)
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || path.Base(u.Path) == "" || path.Base(u.Path) == "." {
		log.Fatal("-vk-link-file does not hold a call link")
	}
	var peer *net.UDPAddr
	if *peerFlag != "" {
		if peer, err = net.ResolveUDPAddr("udp4", *peerFlag); err != nil {
			log.Fatalf("-peer: %v", err)
		}
	}
	var arms []arm
	var longest time.Duration
	for _, f := range strings.Split(*silences, ",") {
		d, err := time.ParseDuration(strings.TrimSpace(f))
		if err != nil || d <= 0 {
			log.Fatalf("-silence: %q is not a duration", f)
		}
		arms = append(arms, arm{name: "silent " + d.String(), silence: d})
		if d > longest {
			longest = d
		}
	}
	if !*noControl {
		arms = append(arms, arm{name: "control", silence: longest, control: true})
	}

	log.Printf("minting one TURN credential (the captcha-free path)…")
	creds, err := proxy.GetVKCreds(path.Base(u.Path), nil, "", "", 0, 0, "", "")
	if err != nil {
		log.Fatalf("credentials: %v", err)
	}
	log.Printf("relay %s over TCP, %d arm(s) on one credential, the longest %s", maskHost(creds.Address), len(arms), longest)

	results := make([]result, len(arms))
	var wg sync.WaitGroup
	for i, a := range arms {
		wg.Add(1)
		go func(i int, a arm) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 300 * time.Millisecond) // not one burst of Allocates
			results[i] = runArm(a, creds.Address, creds, peer)
			log.Printf("[%s] %s — %s", a.name, results[i].verdict, results[i].detail)
		}(i, a)
	}
	wg.Wait()

	sort.SliceStable(results, func(i, j int) bool { return results[i].silence < results[j].silence })
	fmt.Println()
	fmt.Printf("%-14s %-10s %-16s %s\n", "arm", "lifetime", "verdict", "detail")
	for _, r := range results {
		fmt.Printf("%-14s %-10s %-16s %s\n", r.name, r.allocated, r.verdict, r.detail)
	}
}
