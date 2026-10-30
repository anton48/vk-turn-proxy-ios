// turn-relay is its own module: it builds against the vendored fork of
// pion/turn (third_party/pion-turn — the request's MESSAGE-INTEGRITY not
// checked), which the app and the console must never see.
module github.com/cacggghp/vk-turn-proxy/tools/turn-relay

go 1.24

require github.com/pion/turn/v5 v5.0.2

require (
	github.com/pion/dtls/v3 v3.0.10 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v3 v3.1.1 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/pion/turn/v5 => ../../third_party/pion-turn
