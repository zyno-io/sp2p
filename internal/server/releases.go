// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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

// resolvedAsset holds the download URL and version for a cached asset.
type resolvedAsset struct {
	url     string
	version string // tag_name with "v" prefix stripped
}

// ReleaseResolver fetches the GitHub releases list and resolves asset download
// URLs by scanning all releases (not just "latest"). This handles scoped releases
// (e.g. v0.1.1-cli-windows) that only contain a subset of platform assets.
// Draft and prerelease entries are excluded to match /releases/latest semantics.
//
// Call Start to begin periodic background polling and Stop to cancel it.
// On refresh failure, the previous cache is preserved as a stale fallback.
type ReleaseResolver struct {
	client *http.Client
	apiURL string // overridable for testing

	mu         sync.RWMutex
	cache      map[string]resolvedAsset // assetName → resolved asset
	fetchedAt  time.Time
	refreshing bool // prevents concurrent refresh from any caller

	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewReleaseResolver creates a new release resolver.
func NewReleaseResolver() *ReleaseResolver {
	return &ReleaseResolver{
		client: &http.Client{Timeout: releaseHTTPTimeout},
		apiURL: githubReleasesURL,
	}
}

// Start begins periodic background polling of GitHub releases.
// The first fetch happens immediately in the background.
func (r *ReleaseResolver) Start() {
	r.stopCh = make(chan struct{})
	go r.poll()
}

// Stop cancels background polling. Safe to call multiple times.
func (r *ReleaseResolver) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}

func (r *ReleaseResolver) poll() {
	// Initial fetch.
	ctx, cancel := context.WithTimeout(context.Background(), releaseHTTPTimeout)
	if err := r.refresh(ctx); err != nil {
		slog.Warn("release resolver: initial refresh failed", "error", err)
	}
	cancel()

	ticker := time.NewTicker(releaseCacheTTL)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), releaseHTTPTimeout)
			if err := r.refresh(ctx); err != nil {
				slog.Warn("release resolver: periodic refresh failed", "error", err)
			}
			cancel()
		}
	}
}

// ResolveAssetURL returns the download URL for the given asset name by scanning
// GitHub releases from newest to oldest. Results are cached with a 1-minute TTL.
// On refresh failure, stale cache entries are used. Falls back to the standard
// /releases/latest/download/ URL only if no cached data exists.
func (r *ReleaseResolver) ResolveAssetURL(ctx context.Context, assetName string) (string, error) {
	// Check fresh cache.
	r.mu.RLock()
	if r.cache != nil && time.Since(r.fetchedAt) < releaseCacheTTL {
		if a, ok := r.cache[assetName]; ok {
			r.mu.RUnlock()
			return a.url, nil
		}
		r.mu.RUnlock()
		// Asset not in cache — return fallback.
		return r.fallbackURL(assetName), nil
	}
	r.mu.RUnlock()

	// Cache expired or empty — attempt refresh (concurrent calls are deduplicated).
	if err := r.refresh(ctx); err != nil {
		slog.Warn("release resolver: refresh failed", "error", err)
	}

	// Check cache (fresh or stale).
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cache != nil {
		if a, ok := r.cache[assetName]; ok {
			return a.url, nil
		}
	}
	return r.fallbackURL(assetName), nil
}

// LatestVersionForPlatform returns the latest release version that has an asset
// for the given OS/arch combination, or empty string if unknown.
func (r *ReleaseResolver) LatestVersionForPlatform(clientOS, clientArch string) string {
	ext := ".tar.gz"
	if clientOS == "windows" {
		ext = ".zip"
	}
	assetName := fmt.Sprintf("sp2p_%s_%s%s", clientOS, clientArch, ext)

	r.mu.RLock()
	defer r.mu.RUnlock()
	if a, ok := r.cache[assetName]; ok {
		return a.version
	}
	return ""
}

// refresh fetches the releases list from GitHub and rebuilds the cache.
// For each asset name, the first (newest) non-prerelease, non-draft release wins.
// Fetches up to 100 releases in a single request.
// On failure, the existing cache is preserved (not cleared).
// Concurrent calls are deduplicated via the refreshing flag.
func (r *ReleaseResolver) refresh(ctx context.Context) error {
	r.mu.Lock()
	if r.refreshing {
		r.mu.Unlock()
		return nil // another goroutine is already refreshing
	}
	r.refreshing = true
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.refreshing = false
		r.mu.Unlock()
	}()

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

	cache := make(map[string]resolvedAsset)
	// Releases are returned newest-first by GitHub.
	// First occurrence of each asset name wins (newest release).
	for _, rel := range releases {
		if rel.Draft || rel.Prerelease {
			continue
		}
		version := strings.TrimPrefix(rel.TagName, "v")
		for _, asset := range rel.Assets {
			if _, exists := cache[asset.Name]; !exists {
				cache[asset.Name] = resolvedAsset{
					url:     asset.BrowserDownloadURL,
					version: version,
				}
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
