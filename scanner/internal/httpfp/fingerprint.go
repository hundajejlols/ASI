package httpfp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/agh-cbi/asi-scanner/internal/contract"
)

var (
	titleRe      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	iconLinkRe   = regexp.MustCompile(`(?is)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']`)
	iconLinkRe2  = regexp.MustCompile(`(?is)<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*icon[^"']*["']`)
	metaGenRe    = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	metaGenRe2   = regexp.MustCompile(`(?is)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']`)
	stagingRe    = regexp.MustCompile(`(?i)(^|[^a-z0-9])(staging|stage|dev|test|qa|uat|sandbox|preprod|dvwa)([^a-z0-9]|$)`)
	adminTitleRe = regexp.MustCompile(`(?i)(admin|administration|dashboard|control panel|phpmyadmin|adminer|nginx proxy manager|traefik|rabbitmq management|jenkins|grafana|kibana|sign in|log in|login|wp-admin|setup configuration)`)
	pwdInputRe   = regexp.MustCompile(`(?is)<input[^>]+type=["']password["']`)
	poweredCMSRe = regexp.MustCompile(`(?i)powered\s+by\s+([a-z][a-z0-9._-]{2,28}(?:cms|wiki|press|cart|board)?)`)
)

func effectiveURLPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return ""
}

// IsAllowedRedirectTarget sprawdza zarówno host/IP, schemat (http/https), jak i port (chroni przed SSRF na inne porty).
func IsAllowedRedirectTarget(u *url.URL, targetIP string, sniHost string, targetPort int) bool {
	if u == nil {
		return false
	}
	sc := strings.ToLower(u.Scheme)
	if sc != "http" && sc != "https" {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(u.Hostname()))
	hostMatch := h == strings.ToLower(targetIP) || (sniHost != "" && h == strings.ToLower(sniHost))
	if !hostMatch {
		return false
	}
	uPort := effectiveURLPort(u)
	origPort := strconv.Itoa(targetPort)
	if uPort == origPort {
		return true
	}
	// Dozwolona wyłącznie standardowa ścieżka HTTP->HTTPS (80<->443) na tym samym hoście
	if (origPort == "80" && uPort == "443") || (origPort == "443" && uPort == "80") {
		return true
	}
	return false
}

// Probe wykonuje pełny, pasywny fingerprinting HTTP/HTTPS:
// - kod odpowiedzi, tytuł, łańcuch przekierowań (max 5), nagłówki, ciasteczka
// - pełny certyfikat TLS (Subject, Issuer, SAN, NotAfter, IsSelfSigned)
// - favicon MurmurHash3 (standard Shodan: base64 co 76 znaków)
// - detekcję technologii / CMS / frameworków / IoT wraz z oceną pewności (high/medium/low)
// - heurystyki is_staging_env i is_admin_panel
// Zwraca (fingerprint, bodyHTML) na potrzeby silnika sygnatur.
func Probe(
	ctx context.Context,
	ip string,
	hostname *string,
	port int,
	useTLS bool,
	timeout time.Duration,
	rateWait func(context.Context) error,
) (*contract.HTTPFingerprint, string) {
	if ctx.Err() != nil {
		return nil, ""
	}
	if rateWait != nil {
		if err := rateWait(ctx); err != nil {
			return nil, ""
		}
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	hostPort := net.JoinHostPort(ip, strconv.Itoa(port))
	targetURL := fmt.Sprintf("%s://%s/", scheme, hostPort)

	sniHost := ""
	if hostname != nil {
		trimmed := strings.TrimSpace(*hostname)
		if trimmed != "" && net.ParseIP(trimmed) == nil {
			sniHost = trimmed
		}
	}

	isAllowed := func(u *url.URL) bool {
		return IsAllowedRedirectTarget(u, ip, sniHost, port)
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

	redirects := []string{}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			redirects = append(redirects, req.URL.String())
			// Ochrona przed SSRF: zapisujemy cel przekierowania, ale nie podążamy na obcy host lub nieautoryzowany port.
			if !isAllowed(req.URL) {
				return http.ErrUseLastResponse
			}
			if sniHost != "" && strings.EqualFold(req.URL.Hostname(), ip) {
				req.Host = sniHost
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, ""
	}
	if sniHost != "" {
		req.Host = sniHost
	}
	req.Header.Set("User-Agent", "Janus-ASI-Scanner/0.3 (Passive Audit)")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ""
		}
		elapsedMs := int(time.Since(start).Milliseconds())
		probeErr := classifyProbeError(err)
		return &contract.HTTPFingerprint{
			URL:            targetURL,
			Scheme:         scheme,
			StatusCode:     0,
			ResponseTimeMs: &elapsedMs,
			ProbeError:     &probeErr,
			RedirectChain:  redirects,
			Headers:        map[string]string{},
			Cookies:        []string{},
			Technologies:   []string{},
			TechConfidence: map[string]string{},
			IsAdminPanel:   false,
			IsStagingEnv:   false,
		}, ""
	}
	defer resp.Body.Close()

	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	elapsedMs := int(time.Since(start).Milliseconds())
	var probeErrPtr *string
	if readErr != nil && ctx.Err() == nil {
		pe := classifyProbeError(readErr)
		probeErrPtr = &pe
	}
	body := string(bodyBytes)

	var title *string
	if m := titleRe.FindStringSubmatch(body); len(m) > 1 {
		t := strings.TrimSpace(m[1])
		if t != "" {
			title = &t
		}
	}

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	cookies := make([]string, 0, len(resp.Cookies()))
	for _, c := range resp.Cookies() {
		cookies = append(cookies, c.Name)
	}

	var tlsInfo *contract.TLSInfo
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		isSelfSigned := cert.Subject.String() == cert.Issuer.String()
		if !isSelfSigned {
			if err := cert.CheckSignatureFrom(cert); err == nil {
				isSelfSigned = true
			}
		}
		san := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
		san = append(san, cert.DNSNames...)
		for _, ipSan := range cert.IPAddresses {
			san = append(san, ipSan.String())
		}
		tlsInfo = &contract.TLSInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			NotAfter:     cert.NotAfter.UTC(),
			SAN:          san,
			IsSelfSigned: isSelfSigned,
		}
	}

	// Favicon MMH3 (standard Shodan) — tylko w obrębie skanowanego hosta i portu
	var favHash *string
	if ctx.Err() == nil {
		favPath := extractFaviconPath(body)
		if !strings.HasPrefix(strings.ToLower(favPath), "data:") {
			if rateWait == nil || rateWait(ctx) == nil {
				if hash, ok := fetchFaviconMMH3(ctx, client, resp.Request.URL, favPath, sniHost, isAllowed); ok {
					favHash = &hash
				}
			}
		}
	}

	techs, confidence := DetectTechnologiesWithConfidence(headers, cookies, body)
	isStaging := detectStaging(hostname, title, headers, body)
	isAdmin := detectAdminPanel(title, headers, body)

	return &contract.HTTPFingerprint{
		URL:             targetURL,
		Scheme:          scheme,
		StatusCode:      resp.StatusCode,
		ResponseTimeMs:  &elapsedMs,
		ProbeError:      probeErrPtr,
		Title:           title,
		RedirectChain:   redirects,
		Headers:         headers,
		Cookies:         cookies,
		FaviconMMH3Hash: favHash,
		TLS:             tlsInfo,
		Technologies:    techs,
		TechConfidence:  confidence,
		IsAdminPanel:    isAdmin,
		IsStagingEnv:    isStaging,
	}, body
}

func classifyProbeError(err error) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded"):
		return "http_timeout"
	case strings.Contains(lower, "eof"):
		return "connection_eof"
	case strings.Contains(lower, "connection reset"):
		return "connection_reset"
	case strings.Contains(lower, "connection refused"):
		return "connection_refused"
	default:
		msg := strings.TrimSpace(err.Error())
		if len(msg) > 120 {
			msg = msg[:120]
		}
		return msg
	}
}

func extractFaviconPath(body string) string {
	if m := iconLinkRe.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	if m := iconLinkRe2.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return "/favicon.ico"
}

func fetchFaviconMMH3(
	ctx context.Context,
	client *http.Client,
	baseURL *url.URL,
	favPath string,
	sniHost string,
	isAllowedHost func(*url.URL) bool,
) (string, bool) {
	ref, err := url.Parse(favPath)
	if err != nil {
		return "", false
	}
	resolved := baseURL.ResolveReference(ref)
	if !isAllowedHost(resolved) {
		return "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resolved.String(), nil)
	if err != nil {
		return "", false
	}
	if sniHost != "" {
		req.Host = sniHost
	}
	req.Header.Set("User-Agent", "Janus-ASI-Scanner/0.3 (Passive Audit)")

	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil || len(data) == 0 {
		return "", false
	}
	if !isValidFaviconResponse(resp.Header.Get("Content-Type"), data) {
		return "", false
	}

	return ComputeFaviconMMH3(data), true
}

// ComputeFaviconMMH3 wylicza hash MurmurHash3 (standard Shodan: base64 co 76 znaków + '\n').
func ComputeFaviconMMH3(data []byte) string {
	b64 := encodeBase64Shodan(data)
	hash := murmurHash3_32([]byte(b64), 0)
	return strconv.FormatInt(int64(int32(hash)), 10)
}

// isValidFaviconResponse odrzuca odpowiedzi tekstowe/HTML/JSON (soft-404, catch-all typu traefik/whoami),
// akceptując wyłącznie rzeczywiste obrazy/ikony (image/*, magic bytes ICO/PNG/GIF/JPEG/SVG).
func isValidFaviconResponse(headerContentType string, data []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(strings.Split(headerContentType, ";")[0]))
	if ct != "" {
		if strings.HasPrefix(ct, "image/") {
			return true
		}
		if strings.HasPrefix(ct, "text/") ||
			strings.Contains(ct, "html") ||
			strings.Contains(ct, "json") ||
			strings.Contains(ct, "xml") ||
			strings.Contains(ct, "javascript") {
			return false
		}
	}
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 && (data[2] == 0x01 || data[2] == 0x02) && data[3] == 0x00 {
		return true
	}
	detected := strings.ToLower(http.DetectContentType(data))
	if strings.HasPrefix(detected, "image/") {
		return true
	}
	prefixLen := len(data)
	if prefixLen > 128 {
		prefixLen = 128
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(data[:prefixLen]))), "<svg") {
		return true
	}
	return false
}

// encodeBase64Shodan koduje dane w base64 z łamaniem linii co 76 znaków + końcowe \n (kompatybilne z Python codecs/Shodan).
func encodeBase64Shodan(data []byte) string {
	raw := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	sb.Grow(len(raw) + len(raw)/76 + 2)
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		sb.WriteString(raw[i:end])
		sb.WriteByte('\n')
	}
	return sb.String()
}

// murmurHash3_32 implementuje standardowy 32-bitowy MurmurHash3 (x86_32).
func murmurHash3_32(data []byte, seed uint32) uint32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)
	h1 := seed
	nblocks := len(data) / 4

	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

// DetectTechnologiesWithConfidence wykrywa technologie wraz z oceną pewności (high/medium/low) wg liczby niezależnych źródeł.
func DetectTechnologiesWithConfidence(headers map[string]string, cookies []string, body string) ([]string, map[string]string) {
	sources := map[string]map[string]struct{}{}
	addEvidence := func(tech, source string) {
		if _, ok := sources[tech]; !ok {
			sources[tech] = map[string]struct{}{}
		}
		sources[tech][source] = struct{}{}
	}

	lowerHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		lowerHeaders[strings.ToLower(k)] = strings.ToLower(v)
	}

	server := lowerHeaders["server"]
	powered := lowerHeaders["x-powered-by"]
	generator := lowerHeaders["x-generator"]
	wwwAuth := lowerHeaders["www-authenticate"]
	location := lowerHeaders["location"]

	headerChecks := []struct {
		haystack string
		needle   string
		tech     string
	}{
		{server, "nginx", "nginx"},
		{server, "apache", "Apache HTTP Server"},
		{server, "caddy", "Caddy"},
		{server, "microsoft-iis", "Microsoft IIS"},
		{server, "cloudflare", "Cloudflare"},
		{server, "envoy", "Envoy"},
		{server, "gunicorn", "Gunicorn"},
		{server, "uvicorn", "Uvicorn"},
		{server, "werkzeug", "Flask / Werkzeug"},
		{server, "openresty", "OpenResty"},
		{server, "jetty", "Jetty"},
		{server, "tomcat", "Apache Tomcat"},
		{server, "lighttpd", "lighttpd"},
		{server, "cowboy", "Erlang Cowboy"},
		{server, "traefik", "Traefik"},
		// Serwery wbudowane i urządzenia IoT
		{server, "goahead", "GoAhead-Webs (IoT)"},
		{server, "boa/", "Boa Embedded HTTP (IoT)"},
		{server, "rompager", "Allegro RomPager (IoT)"},
		{server, "mini_httpd", "mini_httpd (IoT)"},
		{server, "micro_httpd", "micro_httpd (IoT)"},
		{server, "hikvision", "Hikvision IP Camera (IoT)"},
		{server, "dnvrs-webs", "Hikvision IP Camera (IoT)"},
		{server, "app-webs", "Hikvision IP Camera (IoT)"},
		{server, "dahua", "Dahua IP Camera (IoT)"},
		{server, "mikrotik", "MikroTik RouterOS (IoT)"},
		{server, "routeros", "MikroTik RouterOS (IoT)"},
		{server, "ubnt", "Ubiquiti / UniFi (IoT)"},
		{server, "airos", "Ubiquiti AirOS (IoT)"},
		{server, "synology", "Synology NAS (IoT)"},
		{server, "qnap", "QNAP NAS (IoT)"},
		{server, "tp-link", "TP-Link Device (IoT)"},
		{server, "openwrt", "OpenWrt (IoT)"},
		{server, "uhttpd", "OpenWrt uHTTPd (IoT)"},
		{wwwAuth, "hikvision", "Hikvision IP Camera (IoT)"},
		{wwwAuth, "dahua", "Dahua IP Camera (IoT)"},
		{wwwAuth, "mikrotik", "MikroTik RouterOS (IoT)"},
		{wwwAuth, "routeros", "MikroTik RouterOS (IoT)"},
		{wwwAuth, "tp-link", "TP-Link Device (IoT)"},
		{wwwAuth, "axis", "Axis Network Camera (IoT)"},
		{powered, "php", "PHP"},
		{powered, "express", "Express"},
		{powered, "asp.net", "ASP.NET"},
		{powered, "next.js", "Next.js"},
		{generator, "drupal", "Drupal"},
		{generator, "wordpress", "WordPress"},
		{location, "wp-admin", "WordPress"},
		{location, "wp-login.php", "WordPress"},
		{location, "phpmyadmin", "phpMyAdmin"},
		{location, "adminer", "Adminer"},
		{location, "/dashboard/", "Traefik"},
	}
	for _, chk := range headerChecks {
		if chk.haystack != "" && strings.Contains(chk.haystack, chk.needle) {
			addEvidence(chk.tech, "header")
		}
	}

	if _, ok := lowerHeaders["x-jenkins"]; ok {
		addEvidence("Jenkins", "header")
	}
	if _, ok := lowerHeaders["x-drupal-cache"]; ok {
		addEvidence("Drupal", "header")
	}

	for _, c := range cookies {
		lc := strings.ToLower(c)
		switch {
		case strings.Contains(lc, "phpsessid"):
			addEvidence("PHP", "cookie")
		case strings.Contains(lc, "jsessionid"):
			addEvidence("Java", "cookie")
		case strings.Contains(lc, "wordpress_") || strings.Contains(lc, "wp-settings"):
			addEvidence("WordPress", "cookie")
		case strings.Contains(lc, "phpmyadmin") || strings.Contains(lc, "pma_lang"):
			addEvidence("phpMyAdmin", "cookie")
		case strings.Contains(lc, "adminer_sid"):
			addEvidence("Adminer", "cookie")
		case strings.Contains(lc, "i_like_gitea"):
			addEvidence("Gitea", "cookie")
			addEvidence("Golang", "cookie")
		case strings.Contains(lc, "grafana_session"):
			addEvidence("Grafana", "cookie")
		case strings.Contains(lc, "_gitlab_session"):
			addEvidence("GitLab", "cookie")
		case strings.Contains(lc, "keycloak_"):
			addEvidence("Keycloak", "cookie")
		case strings.Contains(lc, "csrftoken"):
			addEvidence("Django", "cookie")
		}
	}

	lowerBody := strings.ToLower(body)
	bodyChecks := []struct {
		needle string
		tech   string
	}{
		{"wp-content/", "WordPress"},
		{"wp-includes/", "WordPress"},
		{"wp-admin/setup-config.php", "WordPress"},
		{"wordpress &rsaquo; setup", "WordPress"},
		{"drupal.settings", "Drupal"},
		{"joomla!", "Joomla"},
		{"__next_data__", "Next.js"},
		{"data-reactroot", "React"},
		{"ng-version=", "Angular"},
		{"grafana", "Grafana"},
		{"jenkins", "Jenkins"},
		{"phpmyadmin", "phpMyAdmin"},
		{"login - adminer", "Adminer"},
		{"adminer.org", "Adminer"},
		{"nginx proxy manager", "Nginx Proxy Manager"},
		{"rabbitmq management", "RabbitMQ Management"},
		{"powered by gitea", "Gitea"},
		{"go,git,self-hosted,gitea", "Gitea"},
		{"<title>traefik</title>", "Traefik"},
		{"traefik dashboard", "Traefik"},
		{"/api/rawdata", "Traefik"},
		{"httpbin.org", "httpbin"},
		{"damn vulnerable web application", "DVWA"},
		{"dvwa/css/login.css", "DVWA"},
		{"toxiproxy", "Toxiproxy"},
		{"moodle", "Moodle"},
		// Urządzenia IoT / kamery IP / routery / NAS / automatyka
		{"hikvision", "Hikvision IP Camera (IoT)"},
		{"doc/page/login.asp", "Hikvision IP Camera (IoT)"},
		{"dahua", "Dahua IP Camera (IoT)"},
		{"axis communications", "Axis Network Camera (IoT)"},
		{"routeros", "MikroTik RouterOS (IoT)"},
		{"webfig", "MikroTik RouterOS (IoT)"},
		{"openwrt", "OpenWrt (IoT)"},
		{"luci - lua configuration interface", "OpenWrt / LuCI (IoT)"},
		{"home assistant", "Home Assistant (IoT)"},
		{"synology", "Synology NAS (IoT)"},
		{"webman/index.cgi", "Synology NAS (IoT)"},
		{"qnap", "QNAP NAS (IoT)"},
		{"unifi", "Ubiquiti / UniFi (IoT)"},
		{"airos", "Ubiquiti AirOS (IoT)"},
		{"tasmota", "Tasmota (IoT)"},
		{"esphome", "ESPHome (IoT)"},
		{"octoprint", "OctoPrint 3D Printer (IoT)"},
		{"ip camera", "IP Camera (IoT)"},
		{"network camera", "Network Camera (IoT)"},
		{"iot gateway", "IoT Gateway (IoT)"},
	}
	for _, chk := range bodyChecks {
		if strings.Contains(lowerBody, chk.needle) {
			addEvidence(chk.tech, "body")
		}
	}

	// Wykrywanie CMS i wersji z <meta name="generator" content="WordPress 4.7" />
	if genVal := extractMetaGenerator(body); genVal != "" {
		lg := strings.ToLower(genVal)
		switch {
		case strings.Contains(lg, "wordpress"):
			addEvidence("WordPress", "meta")
			addEvidence(genVal, "meta")
		case strings.Contains(lg, "drupal"):
			addEvidence("Drupal", "meta")
			addEvidence(genVal, "meta")
		case strings.Contains(lg, "joomla"):
			addEvidence("Joomla", "meta")
			addEvidence(genVal, "meta")
		default:
			if len(genVal) <= 48 {
				addEvidence(genVal, "meta")
			}
		}
	}

	// Wykrywanie CMS z stopki (np. "Powered by LegacyCMS v1.4.2")
	if m := poweredCMSRe.FindStringSubmatch(body); len(m) > 1 {
		cmsName := strings.TrimSpace(m[1])
		if cmsName != "" {
			addEvidence(cmsName, "footer")
		}
	}

	// Rozpoznawanie traefik/whoami (lekki serwer testowy Go)
	if strings.Contains(body, "Hostname:") && strings.Contains(body, "RemoteAddr:") {
		addEvidence("Golang", "body")
		addEvidence("Traefik Whoami", "body")
	}

	res := make([]string, 0, len(sources))
	conf := make(map[string]string, len(sources))
	for tech, srcSet := range sources {
		res = append(res, tech)
		switch {
		case len(srcSet) >= 2:
			conf[tech] = "high"
		case hasAny(srcSet, "header", "cookie", "meta"):
			conf[tech] = "medium"
		default:
			conf[tech] = "low"
		}
	}
	sort.Strings(res)
	return res, conf
}

func extractMetaGenerator(body string) string {
	if m := metaGenRe.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	if m := metaGenRe2.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func hasAny(m map[string]struct{}, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func detectStaging(hostname *string, title *string, headers map[string]string, body string) bool {
	if hostname != nil && stagingRe.MatchString(*hostname) {
		return true
	}
	if title != nil && stagingRe.MatchString(*title) {
		return true
	}
	for k, v := range headers {
		lk := strings.ToLower(k)
		if lk == "x-environment" || lk == "x-env" || lk == "x-stage" {
			if stagingRe.MatchString(v) {
				return true
			}
		}
	}
	lb := strings.ToLower(body)
	if strings.Contains(lb, "damn vulnerable web application") || strings.Contains(lb, "dvwa/css/login.css") {
		return true
	}
	return false
}

func detectAdminPanel(title *string, headers map[string]string, body string) bool {
	if title != nil && adminTitleRe.MatchString(*title) {
		return true
	}
	for k, v := range headers {
		if strings.EqualFold(k, "location") {
			lv := strings.ToLower(v)
			if strings.Contains(lv, "wp-admin") || strings.Contains(lv, "wp-login") ||
				strings.Contains(lv, "/dashboard") || strings.Contains(lv, "/admin") ||
				strings.Contains(lv, "/login") {
				return true
			}
		}
	}
	if pwdInputRe.MatchString(body) {
		return true
	}
	lb := strings.ToLower(body)
	if strings.Contains(lb, "rabbitmq management") || strings.Contains(lb, "<title>traefik</title>") {
		return true
	}
	return false
}
