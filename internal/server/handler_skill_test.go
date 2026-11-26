// SPDX-License-Identifier: MIT

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

const testSkill = "---\nname: sp2p\ndescription: Move files <safely> & \"fast\" via https://sp2p.io.\n---\n\n# sp2p\n\nGuide at https://sp2p.io/llm\n"

func skillTestServer(t *testing.T, skill []byte, baseURL string) *httptest.Server {
	t.Helper()
	if baseURL != "" {
		// A public base URL makes New() start the GitHub release resolver;
		// serve the skill routes on a bare mux instead to stay offline.
		h, err := NewSkillHandler(skill, baseURL)
		if err != nil {
			t.Fatalf("NewSkillHandler: %v", err)
		}
		mux := http.NewServeMux()
		h.Register(mux)
		ts := httptest.NewServer(mux)
		t.Cleanup(ts.Close)
		return ts
	}
	srv, err := New(Config{Addr: ":0", BaseURL: baseURL, AgentSkill: skill})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		srv.sessions.Stop()
		ts.Close()
	})
	return ts
}

func skillGet(t *testing.T, ts *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestSkill_V2IndexAndDigest(t *testing.T) {
	ts := skillTestServer(t, []byte(testSkill), "")

	resp, body := skillGet(t, ts, "/.well-known/agent-skills/index.json")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status %d type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	var idx struct {
		Schema string `json:"$schema"`
		Skills []struct {
			Name, Type, Description, URL, Digest string
		} `json:"skills"`
	}
	if err := json.Unmarshal(body, &idx); err != nil {
		t.Fatal(err)
	}
	if idx.Schema != "https://schemas.agentskills.io/discovery/0.2.0/schema.json" || len(idx.Skills) != 1 {
		t.Fatalf("bad index: %s", body)
	}
	s := idx.Skills[0]
	wantDesc := `Move files <safely> & "fast" via https://sp2p.io.`
	if s.Name != "sp2p" || s.Type != "skill-md" || s.Description != wantDesc || s.URL != "sp2p/SKILL.md" {
		t.Fatalf("bad skill entry: %+v", s)
	}
	if strings.Contains(string(body), "\\u00") {
		t.Errorf("index HTML-escaped: %s", body)
	}

	// Resolve the entry URL against the index URL, as the skills CLI does.
	ref, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	indexURL, _ := url.Parse("/.well-known/agent-skills/index.json")
	resp, md := skillGet(t, ts, indexURL.ResolveReference(ref).Path)
	if resp.Request.URL.Path != "/.well-known/agent-skills/sp2p/SKILL.md" {
		t.Fatalf("entry URL resolved to %s", resp.Request.URL.Path)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/markdown; charset=utf-8" {
		t.Fatalf("skill status %d type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	sum := sha256.Sum256(md)
	if s.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("digest %s != sha256(body)", s.Digest)
	}
	if string(md) != testSkill {
		t.Error("with no base URL the skill must be served unchanged")
	}
}

func TestSkill_CustomBaseURL(t *testing.T) {
	ts := skillTestServer(t, []byte(testSkill), "https://files.example.com/")

	_, md := skillGet(t, ts, "/.well-known/agent-skills/sp2p/SKILL.md")
	if strings.Contains(string(md), "https://sp2p.io") {
		t.Error("canonical URL not substituted")
	}
	if !strings.Contains(string(md), "https://files.example.com/llm") || strings.Contains(string(md), "com//") {
		t.Errorf("bad substitution: %s", md)
	}
	_, body := skillGet(t, ts, "/.well-known/agent-skills/index.json")
	var idx struct {
		Skills []struct{ Description, Digest string }
	}
	if err := json.Unmarshal(body, &idx); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(md)
	if idx.Skills[0].Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Error("digest mismatch")
	}
	if strings.Contains(idx.Skills[0].Description, "sp2p.io") {
		t.Error("description not substituted")
	}
}

func TestSkill_LegacyIndex(t *testing.T) {
	ts := skillTestServer(t, []byte(testSkill), "")

	_, body := skillGet(t, ts, "/.well-known/skills/index.json")
	var idx map[string]any
	if err := json.Unmarshal(body, &idx); err != nil {
		t.Fatal(err)
	}
	if _, ok := idx["$schema"]; ok || len(idx) != 1 {
		t.Fatalf("legacy index must only have skills: %s", body)
	}
	skills := idx["skills"].([]any)
	e := skills[0].(map[string]any)
	files := e["files"].([]any)
	if len(skills) != 1 || e["name"] != "sp2p" || e["description"] == "" || len(files) != 1 || files[0] != "SKILL.md" {
		t.Fatalf("bad legacy entry: %s", body)
	}
	_, a := skillGet(t, ts, "/.well-known/skills/sp2p/SKILL.md")
	_, b := skillGet(t, ts, "/.well-known/agent-skills/sp2p/SKILL.md")
	if string(a) != string(b) || len(a) == 0 {
		t.Error("legacy and current SKILL.md differ")
	}
}

func TestSkill_MethodsAndHead(t *testing.T) {
	ts := skillTestServer(t, []byte(testSkill), "")
	resp, err := http.Head(ts.URL + "/.well-known/agent-skills/index.json")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("HEAD: %v %v", err, resp)
	}
	resp.Body.Close()
	resp, err = http.Post(ts.URL+"/.well-known/agent-skills/index.json", "text/plain", nil)
	if err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %v %v", err, resp)
	}
	resp.Body.Close()
}

func TestSkill_NoSkill404(t *testing.T) {
	ts := skillTestServer(t, nil, "")
	for _, p := range []string{
		"/.well-known/agent-skills/index.json", "/.well-known/agent-skills/sp2p/SKILL.md",
		"/.well-known/skills/index.json", "/.well-known/skills/sp2p/SKILL.md",
	} {
		if resp, _ := skillGet(t, ts, p); resp.StatusCode != 404 {
			t.Errorf("%s: status %d", p, resp.StatusCode)
		}
	}
}

func TestSkill_InvalidFrontmatter(t *testing.T) {
	long := strings.Repeat("x", 1025)
	cases := map[string]string{
		"no frontmatter": "# hi\n",
		"unterminated":   "---\nname: sp2p\ndescription: d\n",
		"uppercase name": "---\nname: SP2P\ndescription: d\n---\n",
		"double dash":    "---\nname: a--b\ndescription: d\n---\n",
		"leading dash":   "---\nname: -a\ndescription: d\n---\n",
		"trailing dash":  "---\nname: a-\ndescription: d\n---\n",
		"missing name":   "---\ndescription: d\n---\n",
		"long name":      "---\nname: " + strings.Repeat("a", 65) + "\ndescription: d\n---\n",
		"no description": "---\nname: sp2p\n---\n",
		"long desc":      "---\nname: sp2p\ndescription: " + long + "\n---\n",
		"malformed yaml": "---\nname: [\n---\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(Config{Addr: ":0", AgentSkill: []byte(doc)}); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestSkill_RepoFile(t *testing.T) {
	data, err := os.ReadFile("../../plugins/sp2p/skills/sp2p/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	name, desc, err := parseSkillFrontmatter(data)
	if err != nil {
		t.Fatal(err)
	}
	if name != "sp2p" || len(desc) > 1024 {
		t.Errorf("name %q desc len %d", name, len(desc))
	}
	if !strings.Contains(string(data), "https://sp2p.io") {
		t.Error("repo SKILL.md should contain canonical URL")
	}
}
