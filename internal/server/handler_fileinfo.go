// SPDX-License-Identifier: MIT

package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

// FileInfoHandler serves encrypted file metadata via HTTP.
type FileInfoHandler struct {
	sessions *SessionManager
}

func NewFileInfoHandler(sessions *SessionManager) *FileInfoHandler {
	return &FileInfoHandler{sessions: sessions}
}

func (h *FileInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/file-info/")
	if sessionID == "" {
		http.NotFound(w, r)
		return
	}

	session := h.sessions.Get(sessionID)
	if session == nil {
		http.NotFound(w, r)
		return
	}
	data := session.FileInfoData()
	if data == "" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"data": data})
}
