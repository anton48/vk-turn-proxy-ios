package csqtt25

// What a stream's set-up took, stretch by stretch — for the «all ready» line.
//
// «all N agreed workers ready, T after …» is the log's figure for «the tunnel
// whole again», and T alone does not say where it went: a wait for a relay
// credential, the relay's allocation, its permission, the DTLS handshake, the
// server's configuration. The stream that became ready LAST is the one that set
// T, so the line names it and what each stretch of its set-up took. The dial is
// the caller's (DialFunc) and so are its parts: a conn that is a DialStager says
// them; one that is not has the dial as one stretch.

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Stage is one named stretch of a stream's set-up.
type Stage struct {
	Name string
	Took time.Duration
}

// DialStager is what the conn a DialFunc returns MAY be: it says what its dial
// was made of, in order — a wait for a credential, a relay's allocation, its
// permission. Asked once, right behind the dial.
type DialStager interface {
	DialStages() []Stage
}

// streamSetup is one session's set-up as the «all ready» line needs it. Written
// once, before the worker is marked ready; never changed.
type streamSetup struct {
	began  time.Time // the session's first step: its dial
	ready  time.Time
	stages []Stage
}

// dialStages is the dial's part of a set-up: what the conn says of it, or the
// whole dial as one stretch.
func dialStages(conn net.PacketConn, took time.Duration) []Stage {
	if s, ok := conn.(DialStager); ok {
		if st := s.DialStages(); len(st) > 0 {
			return append([]Stage(nil), st...)
		}
	}
	return []Stage{{Name: "dial", Took: took}}
}

// keysStage names the stretch a stream's keys took: a DTLS handshake (whether
// it gave the keys or fell back to the password's), or the password's alone.
func keysStage(mode KeyMode) string {
	if mode == KeysWrap {
		return "keys"
	}
	return "handshake"
}

// words is the «all ready» line's tail about the stream that was ready last:
// when its session began behind the moment all were started (since), and its
// stretches. Nothing for a stream ready before that moment — it took no part.
func (s *streamSetup) words(id int, since time.Time) string {
	if s == nil || s.ready.Before(since) {
		return ""
	}
	began := s.began.Sub(since)
	if began < 0 {
		began = 0
	}
	parts := make([]string, 0, len(s.stages))
	for _, st := range s.stages {
		parts = append(parts, fmt.Sprintf("%s %v", st.Name, st.Took.Round(time.Millisecond)))
	}
	return fmt.Sprintf(" — the last one, worker %d: began +%v, %s", id, began.Round(time.Millisecond), strings.Join(parts, ", "))
}
