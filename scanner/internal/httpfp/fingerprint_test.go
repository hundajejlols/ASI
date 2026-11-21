package httpfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestIsAllowedRedirectTarget(t *testing.T) {
	mustParse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	if !IsAllowedRedirectTarget(mustParse("http://172.28.0.12:80/login"), "172.28.0.12", "staging.agh.local", 80) {
		t.Fatal("same host + same port should be allowed")
	}
	if !IsAllowedRedirectTarget(mustParse("https://staging.agh.local/login"), "172.28.0.12", "staging.agh.local", 80) {
		t.Fatal("HTTP->HTTPS upgrade (80->443) on same SNI host should be allowed")
	}
	if IsAllowedRedirectTarget(mustParse("http://172.28.0.12:6379/"), "172.28.0.12", "staging.agh.local", 80) {
		t.Fatal("port hopping to 6379 on same host must be blocked (SSRF)")
	}
	if IsAllowedRedirectTarget(mustParse("http://169.254.169.254/latest/meta-data/"), "172.28.0.12", "staging.agh.local", 80) {
		t.Fatal("external/metadata host must be blocked")
	}
	if IsAllowedRedirectTarget(mustParse("gopher://172.28.0.12:80/"), "172.28.0.12", "", 80) {
		t.Fatal("non-http/https scheme must be blocked")
	}
}

func TestFaviconValidationAndMMH3(t *testing.T) {
	if isValidFaviconResponse("text/plain; charset=utf-8", []byte("Hostname: whoami\n")) {
		t.Fatal("text/plain must be rejected as invalid favicon")
	}
	icoMagic := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10}
	if !isValidFaviconResponse("application/octet-stream", icoMagic) {
		t.Fatal("valid ICO magic bytes must be accepted")
	}
	h1 := ComputeFaviconMMH3(icoMagic)
	h2 := ComputeFaviconMMH3(icoMagic)
	if h1 == "" || h1 != h2 {
		t.Fatalf("expected deterministic non-empty MMH3 hash, got %q vs %q", h1, h2)
	}
}

func TestDetectTechnologiesWithConfidence(t *testing.T) {
	headers := map[string]string{
		"Server":       "nginx/1.27.2",
		"X-Powered-By": "PHP/8.2",
	}
	cookies := []string{"PHPSESSID"}
	body := `<html><body><footer>Powered by LegacyCMS v1.4.2</footer></body></html>`

	techs, conf := DetectTechnologiesWithConfidence(headers, cookies, body)
	if conf["PHP"] != "high" {
		t.Fatalf("expected PHP confidence=high (header+cookie), got %q (techs=%v)", conf["PHP"], techs)
	}
	if conf["nginx"] != "medium" {
		t.Fatalf("expected nginx confidence=medium (header only), got %q", conf["nginx"])
	}
	if conf["LegacyCMS"] != "low" {
		t.Fatalf("expected LegacyCMS detected with confidence=low (footer), got %q", conf["LegacyCMS"])
	}

	// Sprawdzenie detekcji aplikacji z labu organizatorów (WordPress meta generator, Gitea, Adminer, RabbitMQ, DVWA)
	wpBody := `<html><head><meta name="generator" content="WordPress 4.7" /></head><body><a href="/wp-includes/css/style.css">WP</a></body></html>`
	wpTechs, wpConf := DetectTechnologiesWithConfidence(map[string]string{"Location": "/wp-admin/setup-config.php"}, nil, wpBody)
	if wpConf["WordPress"] != "high" || wpConf["WordPress 4.7"] != "medium" {
		t.Fatalf("expected WordPress (high) and WordPress 4.7 (medium), got techs=%v conf=%v", wpTechs, wpConf)
	}

	giteaTechs, giteaConf := DetectTechnologiesWithConfidence(nil, []string{"i_like_gitea"}, `<html>Powered by Gitea</html>`)
	if giteaConf["Gitea"] != "high" {
		t.Fatalf("expected Gitea confidence=high, got techs=%v conf=%v", giteaTechs, giteaConf)
	}
}

func TestProbeLatencyAndTimeout(t *testing.T) {
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		time.Sleep(120 * time.Millisecond)
		w.Header().Set("Server", "nginx/1.27")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Login - Adminer</title></head><body>adminer.org</body></html>`))
	}))
	defer slowSrv.Close()

	u, _ := url.Parse(slowSrv.URL)
	port, _ := strconv.Atoi(u.Port())

	// 1. Test pomiaru czasu odpowiedzi (symulacja Toxiproxy LATENCY)
	fp, _ := Probe(context.Background(), u.Hostname(), nil, port, false, 2*time.Second, nil)
	if fp == nil || fp.ResponseTimeMs == nil || *fp.ResponseTimeMs < 100 {
		t.Fatalf("expected response_time_ms >= 100, got %+v", fp)
	}
	if fp.ProbeError != nil || !fp.IsAdminPanel {
		t.Fatalf("expected clean probe with IsAdminPanel=true, got err=%v admin=%v", fp.ProbeError, fp.IsAdminPanel)
	}

	// 2. Test rejestracji timeoutu HTTP (symulacja Toxiproxy TIMEOUT)
	fpTimeout, _ := Probe(context.Background(), u.Hostname(), nil, port, false, 40*time.Millisecond, nil)
	if fpTimeout == nil || fpTimeout.ProbeError == nil || *fpTimeout.ProbeError != "http_timeout" {
		t.Fatalf("expected http_timeout probe_error, got %+v", fpTimeout)
	}
}
