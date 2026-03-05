// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	githubReleasesURL  = "https://api.github.com/repos/zyno-io/sp2p/releases"
	releaseCacheTTL    = 1 * time.Minute
	releaseHTTPTimeout = 10 * time.Second
)

// githubRelease is a subset of the GitHub API release response.
type githubRelease struct {
	TagName    string        `json:"tag_name"`
	Prerelease bool          `json:"prerelease"`
	Draft      bool          `json:"draft"`
	Assets     []githubAsset `json:"assets"`
}

// githubAsset is a subset of the GitHub API asset response.
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// ReleaseResolver fetches the GitHub releases list and resolves asset download
// URLs by scanning all releases (not just "latest"). This handles scoped releases
// (e.g. v0.1.1-cli-windows) that only contain a subset of platform assets.
// Draft and prerelease entries are excluded to match /releases/latest semantics.
type ReleaseResolver struct {
	client *http.Client
	apiURL string // overridable for testing

	mu          sync.RWMutex
	cache       map[string]string // assetName → downloadURL
	fetchedAt   time.Time
	refreshing  bool // prevents concurrent refresh stampede
}

// NewReleaseResolver creates a new release resolver.
func NewReleaseResolver() *ReleaseResolver {
	return &ReleaseResolver{
		client: &http.Client{Timeout: releaseHTTPTimeout},
		apiURL: githubReleasesURL,
	}
}

// ResolveAssetURL returns the download URL for the given asset name by scanning
// GitHub releases from newest to oldest. Results are cached with a 1-minute TTL.
// Falls back to the standard /releases/latest/download/ URL if the API is unreachable.
func (r *ReleaseResolver) ResolveAssetURL(ctx context.Context, assetName string) (string, error) {
	r.mu.RLock()
	if r.cache != nil && time.Since(r.fetchedAt) < releaseCacheTTL {
		if u, ok := r.cache[assetName]; ok {
			r.mu.RUnlock()
			return u, nil
		}
		r.mu.RUnlock()
		// Asset not in cache — return fallback.
		return r.fallbackURL(assetName), nil
	}
	r.mu.RUnlock()

	// Cache expired or empty — refresh (only one goroutine at a time).
	r.mu.Lock()
	if r.refreshing {
		// Another goroutine is refreshing — use stale cache or fallback.
		r.mu.Unlock()
		r.mu.RLock()
		defer r.mu.RUnlock()
		if u, ok := r.cache[assetName]; ok {
			return u, nil
		}
		return r.fallbackURL(assetName), nil
	}
	// Double-check: cache may have been refreshed while we waited for the write lock.
	if r.cache != nil && time.Since(r.fetchedAt) < releaseCacheTTL {
		r.mu.Unlock()
		r.mu.RLock()
		defer r.mu.RUnlock()
		if u, ok := r.cache[assetName]; ok {
			return u, nil
		}
		return r.fallbackURL(assetName), nil
	}
	r.refreshing = true
	r.mu.Unlock()

	err := r.refresh(ctx)

	r.mu.Lock()
	r.refreshing = false
	r.mu.Unlock()

	if err != nil {
		slog.Warn("release resolver: refresh failed, using fallback", "error", err)
		return r.fallbackURL(assetName), nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if u, ok := r.cache[assetName]; ok {
		return u, nil
	}
	return r.fallbackURL(assetName), nil
}

// refresh fetches the releases list from GitHub and rebuilds the cache.
// For each asset name, the first (newest) non-prerelease, non-draft release wins.
// Fetches up to 100 releases in a single request.
func (r *ReleaseResolver) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.apiURL+"?per_page=100", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github API returned %d", resp.StatusCode)
	}

	var releases []githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return fmt.Errorf("decode releases: %w", err)
	}

	cache := make(map[string]string)
	// Releases are returned newest-first by GitHub.
	// First occurrence of each asset name wins (newest release).
	for _, rel := range releases {
		if rel.Draft || rel.Prerelease {
			continue
		}
		for _, asset := range rel.Assets {
			if _, exists := cache[asset.Name]; !exists {
				cache[asset.Name] = asset.BrowserDownloadURL
			}
		}
	}

	r.mu.Lock()
	r.cache = cache
	r.fetchedAt = time.Now()
	r.mu.Unlock()

	slog.Info("release resolver: cache refreshed", "assets", len(cache))
	return nil
}

// fallbackURL returns the standard GitHub latest-release URL for the asset.
func (r *ReleaseResolver) fallbackURL(assetName string) string {
	return fmt.Sprintf("%s/%s", githubReleaseBaseURL, assetName)
}
