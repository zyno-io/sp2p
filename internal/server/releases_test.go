// SPDX-License-Identifier: MIT

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestGitHubAPI creates a mock GitHub releases API server returning the given releases.
func newTestGitHubAPI(t *testing.T, releases []githubRelease) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(releases)
	}))
}

// newResolverWithURL creates a ReleaseResolver pointed at a custom API URL.
func newResolverWithURL(apiURL string) *ReleaseResolver {
	r := NewReleaseResolver()
	r.apiURL = apiURL
	return r
}

func TestReleaseResolver_ResolvesFromNewestRelease(t *testing.T) {
	releases := []githubRelease{
		{
			TagName: "v0.2.0",
			Assets: []githubAsset{
				{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.2.0/sp2p_linux_amd64.tar.gz"},
				{Name: "sp2p_darwin_arm64.tar.gz", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.2.0/sp2p_darwin_arm64.tar.gz"},
			},
		},
		{
			TagName: "v0.1.0",
			Assets: []githubAsset{
				{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.1.0/sp2p_linux_amd64.tar.gz"},
			},
		},
	}

	api := newTestGitHubAPI(t, releases)
	defer api.Close()

	r := newResolverWithURL(api.URL)
	got, err := r.ResolveAssetURL(t.Context(), "sp2p_linux_amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/zyno-io/sp2p/releases/download/v0.2.0/sp2p_linux_amd64.tar.gz"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestReleaseResolver_ScopedRelease(t *testing.T) {
	// Newest release only has Windows assets; Linux asset should come from older release.
	releases := []githubRelease{
		{
			TagName: "v0.1.1-cli-windows",
			Assets: []githubAsset{
				{Name: "sp2p_windows_amd64.zip", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.1.1-cli-windows/sp2p_windows_amd64.zip"},
			},
		},
		{
			TagName: "v0.1.0",
			Assets: []githubAsset{
				{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.1.0/sp2p_linux_amd64.tar.gz"},
				{Name: "sp2p_windows_amd64.zip", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.1.0/sp2p_windows_amd64.zip"},
				{Name: "sp2p_amd64.deb", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.1.0/sp2p_amd64.deb"},
			},
		},
	}

	api := newTestGitHubAPI(t, releases)
	defer api.Close()

	r := newResolverWithURL(api.URL)

	// Windows should resolve to the scoped release (newest).
	got, _ := r.ResolveAssetURL(t.Context(), "sp2p_windows_amd64.zip")
	if got != "https://github.com/zyno-io/sp2p/releases/download/v0.1.1-cli-windows/sp2p_windows_amd64.zip" {
		t.Fatalf("windows asset: got %s", got)
	}

	// Linux should resolve to the older release.
	got, _ = r.ResolveAssetURL(t.Context(), "sp2p_linux_amd64.tar.gz")
	if got != "https://github.com/zyno-io/sp2p/releases/download/v0.1.0/sp2p_linux_amd64.tar.gz" {
		t.Fatalf("linux asset: got %s", got)
	}

	// Deb should resolve to the older release.
	got, _ = r.ResolveAssetURL(t.Context(), "sp2p_amd64.deb")
	if got != "https://github.com/zyno-io/sp2p/releases/download/v0.1.0/sp2p_amd64.deb" {
		t.Fatalf("deb asset: got %s", got)
	}
}

func TestReleaseResolver_SkipsPrereleaseAndDraft(t *testing.T) {
	releases := []githubRelease{
		{
			TagName:    "v0.3.0-rc1",
			Prerelease: true,
			Assets: []githubAsset{
				{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/rc1/sp2p_linux_amd64.tar.gz"},
			},
		},
		{
			TagName: "v0.3.0-draft",
			Draft:   true,
			Assets: []githubAsset{
				{Name: "sp2p_darwin_arm64.tar.gz", BrowserDownloadURL: "https://example.com/draft/sp2p_darwin_arm64.tar.gz"},
			},
		},
		{
			TagName: "v0.2.0",
			Assets: []githubAsset{
				{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/v0.2.0/sp2p_linux_amd64.tar.gz"},
				{Name: "sp2p_darwin_arm64.tar.gz", BrowserDownloadURL: "https://example.com/v0.2.0/sp2p_darwin_arm64.tar.gz"},
			},
		},
	}

	api := newTestGitHubAPI(t, releases)
	defer api.Close()

	r := newResolverWithURL(api.URL)

	// Linux should skip the prerelease and resolve to v0.2.0.
	got, _ := r.ResolveAssetURL(t.Context(), "sp2p_linux_amd64.tar.gz")
	if got != "https://example.com/v0.2.0/sp2p_linux_amd64.tar.gz" {
		t.Fatalf("expected v0.2.0 (not prerelease), got %s", got)
	}

	// Darwin should skip the draft and resolve to v0.2.0.
	got, _ = r.ResolveAssetURL(t.Context(), "sp2p_darwin_arm64.tar.gz")
	if got != "https://example.com/v0.2.0/sp2p_darwin_arm64.tar.gz" {
		t.Fatalf("expected v0.2.0 (not draft), got %s", got)
	}
}

func TestReleaseResolver_CacheHit(t *testing.T) {
	var fetchCount atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]githubRelease{
			{
				TagName: "v0.1.0",
				Assets: []githubAsset{
					{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/sp2p_linux_amd64.tar.gz"},
				},
			},
		})
	}))
	defer api.Close()

	r := newResolverWithURL(api.URL)

	// First call triggers fetch.
	r.ResolveAssetURL(t.Context(), "sp2p_linux_amd64.tar.gz")
	// Second call should use cache.
	r.ResolveAssetURL(t.Context(), "sp2p_linux_amd64.tar.gz")

	if fetchCount.Load() != 1 {
		t.Fatalf("expected 1 fetch, got %d", fetchCount.Load())
	}
}

func TestReleaseResolver_CacheTTLExpiry(t *testing.T) {
	var fetchCount atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]githubRelease{
			{
				TagName: "v0.1.0",
				Assets: []githubAsset{
					{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/asset"},
				},
			},
		})
	}))
	defer api.Close()

	r := newResolverWithURL(api.URL)

	// First fetch.
	r.ResolveAssetURL(t.Context(), "sp2p_linux_amd64.tar.gz")
	if fetchCount.Load() != 1 {
		t.Fatalf("expected 1 fetch after first call, got %d", fetchCount.Load())
	}

	// Expire the cache by backdating fetchedAt.
	r.mu.Lock()
	r.fetchedAt = time.Now().Add(-releaseCacheTTL - time.Second)
	r.mu.Unlock()

	// Should trigger a new fetch.
	r.ResolveAssetURL(t.Context(), "sp2p_linux_amd64.tar.gz")
	if fetchCount.Load() != 2 {
		t.Fatalf("expected 2 fetches after TTL expiry, got %d", fetchCount.Load())
	}
}

func TestReleaseResolver_FallbackOnAPIError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer api.Close()

	r := newResolverWithURL(api.URL)
	got, err := r.ResolveAssetURL(t.Context(), "sp2p_linux_amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	want := githubReleaseBaseURL + "/sp2p_linux_amd64.tar.gz"
	if got != want {
		t.Fatalf("fallback URL:\n  got  %s\n  want %s", got, want)
	}
}

func TestReleaseResolver_FallbackOnUnreachable(t *testing.T) {
	// Point to a server that immediately closes.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	api.Close() // close immediately

	r := newResolverWithURL(api.URL)
	got, err := r.ResolveAssetURL(t.Context(), "sp2p_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	want := githubReleaseBaseURL + "/sp2p_darwin_arm64.tar.gz"
	if got != want {
		t.Fatalf("fallback URL:\n  got  %s\n  want %s", got, want)
	}
}

func TestReleaseResolver_FallbackForUnknownAsset(t *testing.T) {
	releases := []githubRelease{
		{
			TagName: "v0.1.0",
			Assets: []githubAsset{
				{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/asset"},
			},
		},
	}
	api := newTestGitHubAPI(t, releases)
	defer api.Close()

	r := newResolverWithURL(api.URL)
	got, err := r.ResolveAssetURL(t.Context(), "sp2p_nonexistent.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	want := githubReleaseBaseURL + "/sp2p_nonexistent.tar.gz"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestReleaseResolver_ConcurrentAccess(t *testing.T) {
	releases := []githubRelease{
		{
			TagName: "v0.1.0",
			Assets: []githubAsset{
				{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/linux"},
				{Name: "sp2p_darwin_arm64.tar.gz", BrowserDownloadURL: "https://example.com/darwin"},
			},
		},
	}
	api := newTestGitHubAPI(t, releases)
	defer api.Close()

	r := newResolverWithURL(api.URL)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		asset := "sp2p_linux_amd64.tar.gz"
		if i%2 == 0 {
			asset = "sp2p_darwin_arm64.tar.gz"
		}
		go func(name string) {
			defer wg.Done()
			_, err := r.ResolveAssetURL(t.Context(), name)
			if err != nil {
				t.Errorf("concurrent resolve: %v", err)
			}
		}(asset)
	}
	wg.Wait()
}
