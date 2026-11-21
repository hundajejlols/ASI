package signatures

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/agh-cbi/asi-scanner/internal/contract"
)

const soft404ProbePath = "/asi-404-probe-9f8a7c6e"

var footerRe = regexp.MustCompile(`(?is)<footer[^>]*>(.*?)</footer>`)

type soft404Baseline struct {
	checked    bool
	statusCode int
	bodyLen    int
	normBody   string
}

// Evaluate dopasowuje wyłącznie pasywne sygnatury do zebranego fingerprintu HTTP i HTML.
// Obsługuje: header, cookie, favicon_hash, html_fragment, footer_version oraz path_probe
// (wyłącznie bezpieczne GET z nagłówkiem Host + SNI, rate-limitingiem i ochroną soft-404).
func Evaluate(
	ctx context.Context,
	fp *contract.HTTPFingerprint,
	body string,
	rules []contract.SignatureRule,
	timeout time.Duration,
	sniHost string,
	rateWait func(context.Context) error,
) []contract.SignatureMatch {
	if fp == nil || len(rules) == 0 {
		return []contract.SignatureMatch{}
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if sniHost != "" {
		tlsCfg.ServerName = sniHost
	}
	transport := &http.Transport{
		TLSClientConfig:   tlsCfg,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Prekompilacja regexów raz dla zestawu reguł
	compiledRe := make(map[string]*regexp.Regexp, len(rules))
	for _, r := range rules {
		switch r.MatchType {
		case "header", "header_match", "html_fragment", "footer_version", "path_probe":
			if r.Pattern != "" {
				if re, err := regexp.Compile(r.Pattern); err == nil {
					compiledRe[r.ID] = re
				}
			}
		}
	}

	var baseline soft404Baseline
	matches := []contract.SignatureMatch{}

	for _, rule := range rules {
		if ctx.Err() != nil {
			break
		}

		switch rule.MatchType {
		case "header", "header_match":
			re := compiledRe[rule.ID]
			if re == nil {
				continue
			}
			for k, v := range fp.Headers {
				line := k + ": " + v
				if re.MatchString(line) {
					matches = append(matches, contract.SignatureMatch{
						SignatureID:   rule.ID,
						SignatureName: rule.Name,
						Evidence:      line,
					})
					break
				}
			}

		case "cookie", "cookie_name":
			for _, c := range fp.Cookies {
				if strings.Contains(strings.ToLower(c), strings.ToLower(rule.Pattern)) {
					matches = append(matches, contract.SignatureMatch{
						SignatureID:   rule.ID,
						SignatureName: rule.Name,
						Evidence:      "cookie=" + c,
					})
					break
				}
			}

		case "favicon_hash":
			if fp.FaviconMMH3Hash != nil && *fp.FaviconMMH3Hash == rule.Pattern {
				matches = append(matches, contract.SignatureMatch{
					SignatureID:   rule.ID,
					SignatureName: rule.Name,
					Evidence:      "favicon_mmh3=" + *fp.FaviconMMH3Hash,
				})
			}

		case "html_fragment":
			if body == "" {
				continue
			}
			re := compiledRe[rule.ID]
			if re == nil {
				continue
			}
			if loc := re.FindString(body); loc != "" {
				matches = append(matches, contract.SignatureMatch{
					SignatureID:   rule.ID,
					SignatureName: rule.Name,
					Evidence:      truncate(strings.TrimSpace(loc), 160),
				})
			}

		case "footer_version":
			if body == "" {
				continue
			}
			footerText := extractFooterSection(body)
			re := compiledRe[rule.ID]
			if re == nil {
				continue
			}
			if loc := re.FindString(footerText); loc != "" {
				matches = append(matches, contract.SignatureMatch{
					SignatureID:   rule.ID,
					SignatureName: rule.Name,
					Evidence:      "footer: " + truncate(strings.TrimSpace(loc), 160),
				})
			}

		case "path_probe":
			if rule.ProbePath == nil || *rule.ProbePath == "" {
				continue
			}
			if !baseline.checked {
				baseline = probeSoft404Baseline(ctx, client, fp.URL, sniHost, rateWait)
			}
			if ctx.Err() != nil {
				break
			}
			if ev, ok := runSafePathProbe(ctx, client, fp.URL, rule, compiledRe[rule.ID], baseline, sniHost, rateWait); ok {
				matches = append(matches, contract.SignatureMatch{
					SignatureID:   rule.ID,
					SignatureName: rule.Name,
					Evidence:      ev,
				})
			}
		}
	}
	return matches
}

func extractFooterSection(body string) string {
	if m := footerRe.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	if len(body) > 4096 {
		return body[len(body)-4096:]
	}
	return body
}

func normalizePathEcho(body, probedPath string) string {
	if probedPath == "" {
		return body
	}
	return strings.ReplaceAll(body, probedPath, "<PATH>")
}

func probeSoft404Baseline(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	sniHost string,
	rateWait func(context.Context) error,
) soft404Baseline {
	b := soft404Baseline{checked: true}
	status, length, body, err := safeGet(ctx, client, baseURL, soft404ProbePath, sniHost, rateWait)
	if err != nil {
		return b
	}
	b.statusCode = status
	b.bodyLen = length
	b.normBody = normalizePathEcho(body, soft404ProbePath)
	return b
}

func runSafePathProbe(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	rule contract.SignatureRule,
	compiled *regexp.Regexp,
	baseline soft404Baseline,
	sniHost string,
	rateWait func(context.Context) error,
) (string, bool) {
	status, length, body, err := safeGet(ctx, client, baseURL, *rule.ProbePath, sniHost, rateWait)
	if err != nil {
		return "", false
	}

	if rule.ExpectedStatus != nil && status != *rule.ExpectedStatus {
		return "", false
	}
	if rule.ExpectedStatus == nil && (status < 200 || status >= 400) {
		return "", false
	}

	// Ochrona przed soft-404:
	// 1) identyczna znormalizowana treść po wycięciu echa ścieżki (catch-all / whoami)
	// 2) taki sam status i niemal identyczna długość (<= 64 B) jak losowa nieistniejąca ścieżka
	if baseline.statusCode != 0 && status == baseline.statusCode {
		normProbe := normalizePathEcho(body, *rule.ProbePath)
		if normProbe == baseline.normBody || absInt(len(normProbe)-len(baseline.normBody)) <= 64 {
			return "", false
		}
	}

	if rule.Pattern != "" {
		if compiled == nil {
			return "", false
		}
		if !compiled.MatchString(body) {
			return "", false
		}
	}

	return fmt.Sprintf("GET %s -> HTTP %d (len=%d)", *rule.ProbePath, status, length), true
}

func safeGet(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	path string,
	sniHost string,
	rateWait func(context.Context) error,
) (int, int, string, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "://") {
		return 0, 0, "", fmt.Errorf("unsafe non-relative probe path: %s", path)
	}
	if rateWait != nil {
		if err := rateWait(ctx); err != nil {
			return 0, 0, "", err
		}
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return 0, 0, "", err
	}
	ref, err := url.Parse(path)
	if err != nil {
		return 0, 0, "", err
	}
	resolved := u.ResolveReference(ref)
	if !strings.EqualFold(resolved.Hostname(), u.Hostname()) || resolved.Port() != u.Port() {
		return 0, 0, "", fmt.Errorf("probe path resolved to different host/port: %s", resolved.Host)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resolved.String(), nil)
	if err != nil {
		return 0, 0, "", err
	}
	if sniHost != "" {
		req.Host = sniHost
	}
	req.Header.Set("User-Agent", "Janus-ASI-Scanner/0.3 (Passive Audit)")

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, len(data), string(data), nil
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
