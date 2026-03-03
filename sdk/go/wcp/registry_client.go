package wcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Data models ───────────────────────────────────────────────────────────────

// VerifyResponse mirrors GET /api/v1/verify/:id response.
type VerifyResponse struct {
	WorkerID             string  `json:"worker_id"`
	Status               string  `json:"status"` // active|revoked|banned|unknown
	CurrentHash          *string `json:"current_hash"`
	Banned               bool    `json:"banned"`
	BanReason            *string `json:"ban_reason"`
	AttestedAt           *string `json:"attested_at"`
	AIGenerated          bool    `json:"ai_generated"`
	AIService            *string `json:"ai_service"`
	AIModel              *string `json:"ai_model"`
	AISessionFingerprint *string `json:"ai_session_fingerprint"`
}

// BanEntry mirrors GET /api/v1/ban-list entry.
type BanEntry struct {
	SHA256       string  `json:"sha256"`
	Reason       string  `json:"reason"`
	ReportedAt   string  `json:"reported_at"`
	Source       string  `json:"source"`
	ReviewStatus *string `json:"review_status,omitempty"`
}

// ── Errors ────────────────────────────────────────────────────────────────────

// RegistryRateLimitError is returned when the registry API responds 429.
type RegistryRateLimitError struct{}

func (e *RegistryRateLimitError) Error() string {
	return "pyhall registry rate limit exceeded — try again later"
}

// ── Client ────────────────────────────────────────────────────────────────────

// RegistryClientOptions configures a RegistryClient.
type RegistryClientOptions struct {
	BaseURL      string
	SessionToken string
	Timeout      time.Duration
	CacheTTL     time.Duration
}

type cachedVerify struct {
	resp VerifyResponse
	at   time.Time
}

// RegistryClient is a thin HTTP client for the pyhall.dev worker registry API.
type RegistryClient struct {
	opts  RegistryClientOptions
	http  *http.Client
	mu    sync.RWMutex
	cache map[string]cachedVerify
}

// NewRegistryClient returns a configured RegistryClient.
// If opts.BaseURL is empty, $PYHALL_REGISTRY_URL or https://api.pyhall.dev is used.
func NewRegistryClient(opts RegistryClientOptions) *RegistryClient {
	if opts.BaseURL == "" {
		if env := os.Getenv("PYHALL_REGISTRY_URL"); env != "" {
			opts.BaseURL = env
		} else {
			opts.BaseURL = "https://api.pyhall.dev"
		}
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.CacheTTL == 0 {
		opts.CacheTTL = 60 * time.Second
	}
	return &RegistryClient{
		opts:  opts,
		http:  &http.Client{Timeout: opts.Timeout},
		cache: make(map[string]cachedVerify),
	}
}

// Verify returns the attestation status for a worker.
// HTTP 404 returns VerifyResponse{Status: "unknown"} — no error (IDOR-safe).
func (c *RegistryClient) Verify(workerID string) (VerifyResponse, error) {
	c.mu.RLock()
	if cv, ok := c.cache[workerID]; ok && time.Since(cv.at) < c.opts.CacheTTL {
		c.mu.RUnlock()
		return cv.resp, nil
	}
	c.mu.RUnlock()

	path := "/api/v1/verify/" + url.PathEscape(workerID)
	resp, err := c.get(path)
	if err != nil {
		return VerifyResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		r := VerifyResponse{WorkerID: workerID, Status: "unknown"}
		c.setCache(workerID, r)
		return r, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return VerifyResponse{}, &RegistryRateLimitError{}
	}
	if resp.StatusCode != http.StatusOK {
		return VerifyResponse{}, fmt.Errorf("registry error: %d", resp.StatusCode)
	}

	var r VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return VerifyResponse{}, fmt.Errorf("registry decode: %w", err)
	}
	c.setCache(workerID, r)
	return r, nil
}

// IsHashBanned returns true if the SHA-256 hash appears in the confirmed ban-list.
func (c *RegistryClient) IsHashBanned(sha256 string) (bool, error) {
	entries, err := c.GetBanList(0)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.SHA256 == sha256 {
			return true, nil
		}
	}
	return false, nil
}

// GetBanList returns confirmed ban-list entries. limit=0 uses server default (500).
func (c *RegistryClient) GetBanList(limit int) ([]BanEntry, error) {
	path := "/api/v1/ban-list"
	if limit > 0 {
		path = fmt.Sprintf("%s?limit=%d", path, limit)
	}
	resp, err := c.get(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &RegistryRateLimitError{}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry error: %d", resp.StatusCode)
	}

	var entries []BanEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("registry decode: %w", err)
	}
	return entries, nil
}

// Health returns the /health response body.
func (c *RegistryClient) Health() (map[string]any, error) {
	resp, err := c.get("/health")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry error: %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("registry decode: %w", err)
	}
	return out, nil
}

// Prefetch pre-populates the verify cache for the given worker IDs.
// Network errors for individual workers are silently ignored (non-fatal).
// RegistryRateLimitError is propagated.
func (c *RegistryClient) Prefetch(workerIDs []string) error {
	for _, wid := range workerIDs {
		if _, err := c.Verify(wid); err != nil {
			if _, ok := err.(*RegistryRateLimitError); ok {
				return err
			}
			// Other errors (404 already handled inside Verify) are non-fatal
		}
	}
	return nil
}

// BaseURL returns the configured registry base URL.
func (c *RegistryClient) BaseURL() string { return c.opts.BaseURL }

// GetWorkerHash returns (currentHash, true) for active workers.
// Returns ("", false) for unknown, revoked, or banned workers.
// Suitable as RouterOptions.GetWorkerHash.
func (c *RegistryClient) GetWorkerHash(workerID string) (string, bool) {
	r, err := c.Verify(workerID)
	if err != nil {
		return "", false
	}
	if r.Status != "active" || r.CurrentHash == nil {
		return "", false
	}
	return *r.CurrentHash, true
}

// ── Internals ─────────────────────────────────────────────────────────────────

func (c *RegistryClient) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.opts.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.opts.SessionToken != "" {
		req.Header.Set("Cookie", "pyhall_session="+c.opts.SessionToken)
	}
	return c.http.Do(req)
}

func (c *RegistryClient) setCache(workerID string, r VerifyResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[workerID] = cachedVerify{resp: r, at: time.Now()}
}

// bodyString reads and closes the response body as a string (for error messages).
func bodyString(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return string(b)
}
