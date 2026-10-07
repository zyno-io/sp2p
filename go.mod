module github.com/zyno-io/sp2p

go 1.27.0

require (
	github.com/coder/websocket v1.8.15
	github.com/huin/goupnp v1.3.0
	github.com/klauspost/compress v1.20.1
	github.com/mdp/qrterminal/v3 v3.2.1
	github.com/pion/logging v0.2.4
	github.com/pion/stun/v4 v4.0.1
	github.com/pion/turn/v5 v5.1.2
	github.com/pion/webrtc/v4 v4.2.22
	golang.org/x/crypto v0.57.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/pion/datachannel v1.6.3 // indirect
	github.com/pion/dtls/v3 v3.1.9 // indirect
	github.com/pion/ice/v4 v4.4.4 // indirect
	github.com/pion/interceptor v0.1.49 // indirect
	github.com/pion/mdns/v2 v2.2.1 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.18 // indirect
	github.com/pion/rtp v1.10.5 // indirect
	github.com/pion/sctp v1.11.3 // indirect
	github.com/pion/sdp/v3 v3.0.20 // indirect
	github.com/pion/srtp/v3 v3.1.0 // indirect
	github.com/pion/transport/v5 v5.1.1 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	rsc.io/qr v0.2.0 // indirect
)

// Temporary: pion/ice v4.4.4 plus a fix for the controlling agent retrying an
// asymmetric nomination forever (WebKit on multi-homed macOS loses lanes).
// Upstream: https://github.com/pion/ice/pull/1021 (ice v5). Remove once the pion/webrtc
// version we use includes that fix.
replace github.com/pion/ice/v4 => github.com/zynoconsulting/ice/v4 v4.4.5-0.20261001013836-36c12019e993
