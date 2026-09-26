// SPDX-License-Identifier: MIT

package conn

import (
	"strings"
	"testing"

	"github.com/pion/webrtc/v4"
)

// These assert the offer-construction policy directly with pion, with no
// network involved: a browser-peer offer must carry the media-less video
// buffer hint (recvonly, VP8-only), and a CLI-peer offer must never carry a
// video section at all. A mutation that drops the hint, or that widens the
// registered codec beyond VP8, changes what these offers contain.

func TestOfferToBrowserPeerCarriesVP8OnlyBufferHint(t *testing.T) {
	pc, err := newOfferPeerConnection(webrtc.SettingEngine{}, webrtc.Configuration{}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.CreateDataChannel(dataChannelLabel, nil); err != nil {
		t.Fatal(err)
	}

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}

	section := videoSection(t, offer.SDP)
	if !strings.Contains(section, "a=recvonly") {
		t.Fatalf("video section is not recvonly:\n%s", section)
	}
	assertOnlyVP8Rtpmap(t, section)
}

func TestOfferToCLIPeerHasNoVideoSection(t *testing.T) {
	pc, err := newOfferPeerConnection(webrtc.SettingEngine{}, webrtc.Configuration{}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.CreateDataChannel(dataChannelLabel, nil); err != nil {
		t.Fatal(err)
	}

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(offer.SDP, "m=video") {
		t.Fatalf("CLI-peer offer unexpectedly carries a video section:\n%s", offer.SDP)
	}
}

func TestNewOfferPeerConnectionSkipsHintForAnswerer(t *testing.T) {
	// The answering side of a browser-peer connection never proposes SDP, so
	// it must not add the buffer hint transceiver either.
	pc, err := newOfferPeerConnection(webrtc.SettingEngine{}, webrtc.Configuration{}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.CreateDataChannel(dataChannelLabel, nil); err != nil {
		t.Fatal(err)
	}

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(offer.SDP, "m=video") {
		t.Fatalf("answerer-side offer unexpectedly carries a video section:\n%s", offer.SDP)
	}
}

// videoSection extracts the m=video media section from an SDP so codec and
// direction checks never accidentally match the DataChannel's own section.
func videoSection(t *testing.T, sdp string) string {
	t.Helper()
	lines := strings.Split(sdp, "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "m=video") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no m=video section in SDP:\n%s", sdp)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "m=") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// assertOnlyVP8Rtpmap fails if the video section's rtpmap lines reference
// anything other than VP8, matching newWebRTCAPI's single registered codec.
func assertOnlyVP8Rtpmap(t *testing.T, section string) {
	t.Helper()
	found := false
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "a=rtpmap:") {
			continue
		}
		found = true
		if !strings.Contains(line, "VP8") {
			t.Fatalf("video section rtpmap is not VP8-only: %q", line)
		}
	}
	if !found {
		t.Fatalf("video section has no rtpmap lines:\n%s", section)
	}
}
