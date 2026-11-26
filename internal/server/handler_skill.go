// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	skillCanonicalURL = "https://sp2p.io"
	skillSchemaURL    = "https://schemas.agentskills.io/discovery/0.2.0/schema.json"
	skillMaxDescLen   = 1024
	skillMaxNameLen   = 64
)

var skillNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// SkillHandler serves an Agent Skill for `npx skills add <server>` discovery.
// Everything is precomputed at construction so the digest always matches the
// exact bytes served.
type SkillHandler struct {
	name    string
	body    []byte // served SKILL.md (base URL substituted)
	v2Index []byte
	legacy  []byte
	enabled bool
}

// NewSkillHandler builds a handler from the repo's SKILL.md, substituting
// baseURL for the canonical https://sp2p.io. Empty skill bytes yield a handler
// that serves 404s; invalid skill bytes return an error.
func NewSkillHandler(skill []byte, baseURL string) (*SkillHandler, error) {
	h := &SkillHandler{}
	if len(skill) == 0 {
		return h, nil
	}

	body := skill
	if base := strings.TrimRight(baseURL, "/"); base != "" {
		body = bytes.ReplaceAll(skill, []byte(skillCanonicalURL), []byte(base))
	}

	name, desc, err := parseSkillFrontmatter(body)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(body)
	v2, err := marshalNoEscape(map[string]any{
		"$schema": skillSchemaURL,
		"skills": []map[string]string{{
			"name":        name,
			"type":        "skill-md",
			"description": desc,
			// Relative to the index URL, so it also resolves under a path-prefix proxy.
			"url":    name + "/SKILL.md",
			"digest": "sha256:" + hex.EncodeToString(sum[:]),
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal index: %w", err)
	}
	legacy, err := marshalNoEscape(map[string]any{
		"skills": []map[string]any{{
			"name":        name,
			"description": desc,
			"files":       []string{"SKILL.md"},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal legacy index: %w", err)
	}

	h.name, h.body, h.v2Index, h.legacy, h.enabled = name, body, v2, legacy, true
	return h, nil
}

// Register adds the discovery routes to mux.
func (h *SkillHandler) Register(mux *http.ServeMux) {
	name := h.name
	if name == "" {
		name = "sp2p"
	}
	for _, root := range []string{"/.well-known/agent-skills", "/.well-known/skills"} {
		index := h.v2Index
		if root == "/.well-known/skills" {
			index = h.legacy
		}
		mux.HandleFunc(root+"/index.json", h.serve(func() []byte { return index }, "application/json"))
		mux.HandleFunc(root+"/"+name+"/SKILL.md", h.serve(func() []byte { return h.body }, "text/markdown; charset=utf-8"))
	}
}

func (h *SkillHandler) serve(content func() []byte, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.enabled {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setSecurityHeaders(w)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", contentType)
		w.Write(content())
	}
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// parseSkillFrontmatter extracts and validates name and description from the
// YAML frontmatter of a SKILL.md document.
func parseSkillFrontmatter(doc []byte) (name, desc string, err error) {
	s := strings.ReplaceAll(string(doc), "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return "", "", fmt.Errorf("SKILL.md: missing YAML frontmatter")
	}
	rest := s[len("---\n"):]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		if !strings.HasSuffix(rest, "\n---") {
			return "", "", fmt.Errorf("SKILL.md: unterminated YAML frontmatter")
		}
		end = len(rest) - len("\n---")
	}
	var fm struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(rest[:end]), &fm); err != nil {
		return "", "", fmt.Errorf("SKILL.md: parse frontmatter: %w", err)
	}
	n := fm.Name
	if len(n) < 1 || len(n) > skillMaxNameLen || !skillNameRe.MatchString(n) ||
		strings.HasPrefix(n, "-") || strings.HasSuffix(n, "-") || strings.Contains(n, "--") {
		return "", "", fmt.Errorf("SKILL.md: invalid skill name %q", n)
	}
	d := strings.TrimSpace(fm.Description)
	if d == "" {
		return "", "", fmt.Errorf("SKILL.md: missing description")
	}
	if utf8.RuneCountInString(d) > skillMaxDescLen {
		return "", "", fmt.Errorf("SKILL.md: description exceeds %d characters", skillMaxDescLen)
	}
	return n, d, nil
}
