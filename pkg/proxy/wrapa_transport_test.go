// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWrapATransportPolicyLearnsWithoutFlapping(t *testing.T) {
	p := newWrapATransportPolicy(false) // keep the user's manual TCP choice as the initial preference
	now := time.Unix(1000, 0)
	t0, epoch := p.pick(0, 4, now)
	t1, _ := p.pick(1, 4, now)
	if t0 != "tcp" || t1 != "udp" {
		t.Fatalf("initial exploration: %s %s", t0, t1)
	}
	p.success(epoch, "tcp", 100*time.Millisecond, now)
	p.success(epoch, "udp", 90*time.Millisecond, now)
	if got, _ := p.pick(0, 1, now); got != "tcp" {
		t.Fatalf("10%% jitter changed preference to %s", got)
	}
	for range 3 {
		p.success(epoch, "udp", 50*time.Millisecond, now)
	}
	if got, _ := p.pick(0, 1, now); got != "udp" {
		t.Fatalf("material improvement ignored: %s", got)
	}
}

func TestWrapAStabilityHooksStayOnTheDataPath(t *testing.T) {
	body := goFuncBody(t, "proxy.go", "func (p *Proxy) runWrapASession(")
	if !strings.Contains(body, "p.writePacket(item, connIdx, writeOne)") {
		t.Fatal("WRAP-A writes lost per-connection accounting")
	}
	keepalive := strings.Index(body, "WRAP-A keepalive failed")
	if keepalive < 0 || !strings.Contains(body[keepalive:keepalive+300], "connCancel()") {
		t.Fatal("a failed WRAP-A keepalive no longer restarts the session")
	}
}

func TestWrapAAutoTransportCrossesTheIOSBridge(t *testing.T) {
	b, err := os.ReadFile("../../WireGuardBridge/bridge.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "WrapAAutoTURN bool") ||
		!strings.Contains(s, "`json:\"wrap_a_auto_turn,omitempty\"`") ||
		!strings.Contains(s, "WrapAAutoTURN:    pcfg.WrapAAutoTURN") {
		t.Fatal("the iOS proxy_config no longer carries WRAP-A automatic transport into proxy.Config")
	}
}

func TestWrapATransportPolicyFailureCooldownAndPathReset(t *testing.T) {
	p := newWrapATransportPolicy(true)
	now := time.Unix(1000, 0)
	name, epoch := p.pick(0, 1, now)
	if name != "udp" {
		t.Fatal(name)
	}
	p.failure(epoch, name, now)
	if got, _ := p.pick(0, 1, now.Add(time.Second)); got != "tcp" {
		t.Fatalf("fallback=%s", got)
	}
	p.reset()
	p.success(epoch, "tcp", time.Millisecond, now) // stale result from the old network
	if got, _ := p.pick(0, 1, now); got != "udp" {
		t.Fatalf("old network contaminated reset: %s", got)
	}
}

func TestWrapATransportFailureClassification(t *testing.T) {
	for _, err := range []error{context.DeadlineExceeded, &net.DNSError{IsTimeout: true}, errors.New("all retransmissions failed")} {
		if !isWrapATransportFailure(err) {
			t.Fatalf("network failure ignored: %v", err)
		}
	}
	for _, err := range []error{errors.New("TURN allocate: 486 Allocation Quota Reached"), errors.New("TURN auth failed: 401"), errors.New("getconf: denied: wrong_password"), errors.New("getconf: server returned NOCONF")} {
		if isWrapATransportFailure(err) {
			t.Fatalf("server refusal changed transport: %v", err)
		}
	}
}
