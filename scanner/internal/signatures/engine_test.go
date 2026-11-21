package signatures

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agh-cbi/asi-scanner/internal/contract"
)

func TestEvaluateVirtualHostAndSoft404(t *testing.T) {
	// Serwer testowy wymagający nagłówka Host: admin.agh.local dla /admin oraz zwracający echo soft-404 dla innych
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" && r.Host == "admin.agh.local" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><title>Admin Dashboard</title><body>Welcome to AGH Admin Control Panel with lots of extra content to exceed baseline delta.</body></html>")
			return
		}
		if r.URL.Path == "/catchall" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Echo path: %s | status=ok", r.URL.Path)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "404 Not Found")
	}))
	defer srv.Close()

	fp := &contract.HTTPFingerprint{
		URL:     srv.URL + "/",
		Scheme:  "http",
		Headers: map[string]string{"Server": "nginx/1.27.2", "X-Powered-By": "PHP/8.1"},
		Cookies: []string{"PHPSESSID"},
	}

	adminPath := "/admin"
	status200 := 200
	rules := []contract.SignatureRule{
		{ID: "1", Name: "Admin VHost", MatchType: "path_probe", Pattern: `(?i)admin`, ProbePath: &adminPath, ExpectedStatus: &status200},
		{ID: "2", Name: "PHP Cookie", MatchType: "cookie", Pattern: "PHPSESSID"},
		{ID: "3", Name: "Footer Ver", MatchType: "footer_version", Pattern: `(?i)powered by\s+\S+\s+v\d+\.\d+`},
	}

	body := "<html><footer>Powered by Moodle v4.3</footer></html>"
	matches := Evaluate(context.Background(), fp, body, rules, 3*time.Second, "admin.agh.local", nil)
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches (including vhost /admin), got %d: %+v", len(matches), matches)
	}

	// Bez poprawnego SNI/Host vhost /admin nie powinien dopasować
	matchesNoHost := Evaluate(context.Background(), fp, body, rules, 3*time.Second, "", nil)
	if len(matchesNoHost) != 2 {
		t.Fatalf("expected 2 matches without vhost Host header, got %d", len(matchesNoHost))
	}
}

func TestSoft404PathEchoRejection(t *testing.T) {
	// Serwer zachowujący się jak traefik/whoami (zwraca HTTP 200 z echem ścieżki dla wszystkiego)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "GET %s HTTP/1.1\nHost: %s\nUser-Agent: test\nAdmin keyword in boilerplate\n", r.URL.Path, r.Host)
	}))
	defer srv.Close()

	fp := &contract.HTTPFingerprint{URL: srv.URL + "/", Scheme: "http"}
	longPath := "/very/long/custom/admin/dashboard/endpoint/path/longer/than/sixty/four/bytes/to/test/echo"
	status200 := 200
	rules := []contract.SignatureRule{
		{ID: "1", Name: "Admin Echo Test", MatchType: "path_probe", Pattern: `(?i)admin`, ProbePath: &longPath, ExpectedStatus: &status200},
	}

	matches := Evaluate(context.Background(), fp, "", rules, 3*time.Second, "", nil)
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches on path-echoing soft-404 server, got %+v", matches)
	}
}
