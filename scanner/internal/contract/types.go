package contract

import "time"

// --- Zadanie (Backend -> Redis -> Scanner) ---

type ScanProfile struct {
	NmapFlags              string `json:"nmap_flags"`
	Ports                  string `json:"ports"`
	RateLimitPPS           int    `json:"rate_limit_pps"`
	HTTPFingerprintEnabled bool   `json:"http_fingerprint_enabled"`
	SignaturesEnabled      bool   `json:"signatures_enabled"`
}

type SignatureRule struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Severity       string  `json:"severity"`
	MatchType      string  `json:"match_type"`
	Pattern        string  `json:"pattern"`
	ProbePath      *string `json:"probe_path,omitempty"`
	ExpectedStatus *int    `json:"expected_status,omitempty"`
}

type ScanJobChunk struct {
	SchemaVersion     string          `json:"schema_version"`
	ScanRunID         string          `json:"scan_run_id"`
	ChunkID           string          `json:"chunk_id"`
	TargetCIDR        string          `json:"target_cidr"`
	WindowDeadlineUTC time.Time       `json:"window_deadline_utc"`
	Profile           ScanProfile     `json:"profile"`
	Signatures        []SignatureRule `json:"signatures"`
}

// --- Wynik (Scanner -> Backend) ---

type TLSInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotAfter     time.Time `json:"not_after"`
	SAN          []string  `json:"san"`
	IsSelfSigned bool      `json:"is_self_signed"`
}

type HTTPFingerprint struct {
	URL             string            `json:"url"`
	Scheme          string            `json:"scheme"`
	StatusCode      int               `json:"status_code"`
	ResponseTimeMs  *int              `json:"response_time_ms,omitempty"`
	ProbeError      *string           `json:"probe_error,omitempty"`
	Title           *string           `json:"title,omitempty"`
	RedirectChain   []string          `json:"redirect_chain"`
	Headers         map[string]string `json:"headers"`
	Cookies         []string          `json:"cookies"`
	FaviconMMH3Hash *string           `json:"favicon_mmh3_hash,omitempty"`
	TLS             *TLSInfo          `json:"tls,omitempty"`
	Technologies    []string          `json:"technologies"`
	TechConfidence  map[string]string `json:"tech_confidence,omitempty"`
	IsAdminPanel    bool              `json:"is_admin_panel"`
	IsStagingEnv    bool              `json:"is_staging_env"`
}

type SignatureMatch struct {
	SignatureID   string `json:"signature_id"`
	SignatureName string `json:"signature_name"`
	Evidence      string `json:"evidence"`
}

type ServiceResult struct {
	Port             int              `json:"port"`
	Protocol         string           `json:"protocol"`
	State            string           `json:"state"`
	ServiceName      *string          `json:"service_name,omitempty"`
	Product          *string          `json:"product,omitempty"`
	Version          *string          `json:"version,omitempty"`
	Banner           *string          `json:"banner,omitempty"`
	HTTP             *HTTPFingerprint `json:"http,omitempty"`
	SignatureMatches []SignatureMatch `json:"signature_matches"`
}

type HostResult struct {
	IP       string          `json:"ip"`
	Hostname *string         `json:"hostname,omitempty"`
	IsUp     bool            `json:"is_up"`
	Services []ServiceResult `json:"services"`
}

type ScanChunkResult struct {
	SchemaVersion string       `json:"schema_version"`
	ScanRunID     string       `json:"scan_run_id"`
	ChunkID       string       `json:"chunk_id"`
	WorkerID      string       `json:"worker_id"`
	Status        string       `json:"status"` // completed | requeued_window | failed
	ErrorMessage  *string      `json:"error_message,omitempty"`
	StartedAt     time.Time    `json:"started_at"`
	FinishedAt    time.Time    `json:"finished_at"`
	Hosts         []HostResult `json:"hosts"`
}
