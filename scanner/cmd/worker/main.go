package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/agh-cbi/asi-scanner/internal/config"
	"github.com/agh-cbi/asi-scanner/internal/contract"
	"github.com/agh-cbi/asi-scanner/internal/httpfp"
	"github.com/agh-cbi/asi-scanner/internal/nmap"
	"github.com/agh-cbi/asi-scanner/internal/signatures"
)

var ingestHTTPClient = &http.Client{Timeout: 60 * time.Second}

type httpRateLimiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

func newHTTPRateLimiter(maxRPS int) *httpRateLimiter {
	if maxRPS < 1 {
		maxRPS = 20
	}
	rl := &httpRateLimiter{
		tokens: make(chan struct{}, maxRPS),
		stop:   make(chan struct{}),
	}
	for i := 0; i < maxRPS; i++ {
		rl.tokens <- struct{}{}
	}
	interval := time.Second / time.Duration(maxRPS)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-rl.stop:
				return
			case <-ticker.C:
				select {
				case rl.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return rl
}

func (rl *httpRateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-rl.tokens:
		return nil
	}
}

func (rl *httpRateLimiter) Close() {
	close(rl.stop)
}

func recoverOrphanedProcessingJobs(ctx context.Context, rdb *redis.Client, jobQueue, procQueue string) {
	recovered := 0
	for {
		_, err := rdb.LMove(ctx, procQueue, jobQueue, "RIGHT", "LEFT").Result()
		if err != nil {
			if !errors.Is(err, redis.Nil) {
				log.Printf("[asi-scanner] processing recovery warning: %v", err)
			}
			break
		}
		recovered++
	}
	if recovered > 0 {
		log.Printf("[asi-scanner] recovered %d orphaned job(s) from %s -> %s", recovered, procQueue, jobQueue)
	}
}

func main() {
	cfg := config.Load()
	processingQueue := cfg.RedisJobQueue + ":processing:" + cfg.WorkerID
	log.Printf("[asi-scanner] start worker=%s chunk_workers=%d http_concurrency=%d http_max_rps=%d queue=%s",
		cfg.WorkerID, cfg.ChunkWorkers, cfg.Concurrency, cfg.HTTPMaxRPS, cfg.RedisJobQueue)

	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("invalid REDIS_URL: %v", err)
	}
	rdb := redis.NewClient(opt)
	defer rdb.Close()

	rootCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Odzyskiwanie nieukończonych paczek z kolejki processing tego workera po wcześniejszym crashu
	recoverOrphanedProcessingJobs(rootCtx, rdb, cfg.RedisJobQueue, processingQueue)

	rl := newHTTPRateLimiter(cfg.HTTPMaxRPS)
	defer rl.Close()

	var wg sync.WaitGroup
	for i := 0; i < cfg.ChunkWorkers; i++ {
		slot := i + 1
		wg.Add(1)
		go func(slotID int) {
			defer wg.Done()
			for {
				select {
				case <-rootCtx.Done():
					return
				default:
				}

				// Niezawodne pobranie (BLMove) -> przenosi paczkę do kolejki processing na czas przetwarzania
				rawPayload, err := rdb.BLMove(rootCtx, cfg.RedisJobQueue, processingQueue, "LEFT", "RIGHT", 5*time.Second).Result()
				if err != nil {
					if errors.Is(err, redis.Nil) || errors.Is(err, context.Canceled) {
						continue
					}
					log.Printf("[asi-scanner] slot=%d redis pop error: %v", slotID, err)
					time.Sleep(2 * time.Second)
					continue
				}

				var job contract.ScanJobChunk
				if err := json.Unmarshal([]byte(rawPayload), &job); err != nil {
					log.Printf("[asi-scanner] slot=%d invalid job json: %v", slotID, err)
					_ = rdb.LRem(context.Background(), processingQueue, 1, rawPayload).Err()
					continue
				}

				processJob(rootCtx, cfg, job, rl.Wait)
				_ = rdb.LRem(context.Background(), processingQueue, 1, rawPayload).Err()
			}
		}(slot)
	}

	wg.Wait()
	log.Println("[asi-scanner] graceful shutdown")
}

func processJob(
	parentCtx context.Context,
	cfg config.Config,
	job contract.ScanJobChunk,
	rateWait func(context.Context) error,
) {
	startedAt := time.Now().UTC()
	log.Printf("[asi-scanner] picked chunk=%s target=%s deadline=%s sigs=%d",
		job.ChunkID, job.TargetCIDR, job.WindowDeadlineUTC.Format(time.RFC3339), len(job.Signatures))

	result := contract.ScanChunkResult{
		SchemaVersion: "1.0",
		ScanRunID:     job.ScanRunID,
		ChunkID:       job.ChunkID,
		WorkerID:      cfg.WorkerID,
		StartedAt:     startedAt,
		Hosts:         []contract.HostResult{},
	}

	// 1. Twarda kontrola okna czasowego przed startem nmap
	if time.Now().UTC().After(job.WindowDeadlineUTC) {
		log.Printf("[asi-scanner] window already expired before nmap for chunk=%s", job.ChunkID)
		result.Status = "requeued_window"
		result.FinishedAt = time.Now().UTC()
		postResult(cfg, result)
		return
	}

	ctx, cancel := context.WithDeadline(parentCtx, job.WindowDeadlineUTC)
	defer cancel()

	if job.Profile.RateLimitPPS <= 0 && cfg.DefaultRateLimitPPS > 0 {
		job.Profile.RateLimitPPS = cfg.DefaultRateLimitPPS
	}

	hosts, err := nmap.Run(ctx, job.TargetCIDR, job.Profile)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || parentCtx.Err() != nil {
			log.Printf("[asi-scanner] window deadline or shutdown hit during nmap for chunk=%s -> requeued_window", job.ChunkID)
			result.Status = "requeued_window"
		} else {
			errMsg := err.Error()
			result.Status = "failed"
			result.ErrorMessage = &errMsg
		}
		result.FinishedAt = time.Now().UTC()
		postResult(cfg, result)
		return
	}

	// 2. Współbieżny HTTP/HTTPS fingerprinting + silnik pasywnych sygnatur
	// z pulą goroutines ograniczoną semaforem cfg.Concurrency, rate-limiterem HTTP oraz kontrolą window_deadline_utc.
	httpTimeout := time.Duration(cfg.HTTPTimeoutSec) * time.Second
	if job.Profile.HTTPFingerprintEnabled {
		concurrency := cfg.Concurrency
		if concurrency < 1 {
			concurrency = 4
		}
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		type webTarget struct {
			hostIdx int
			svcIdx  int
		}
		var targets []webTarget
		for hi := range hosts {
			for si := range hosts[hi].Services {
				svc := &hosts[hi].Services[si]
				if svc.State == "open" && isWebPort(svc.Port, svc.ServiceName, svc.Product, svc.Banner) {
					targets = append(targets, webTarget{hostIdx: hi, svcIdx: si})
				}
			}
		}

		for _, wt := range targets {
			if ctx.Err() != nil {
				break
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break
			}
			if ctx.Err() != nil {
				break
			}

			wg.Add(1)
			go func(hi, si int) {
				defer wg.Done()
				defer func() { <-sem }()

				if ctx.Err() != nil {
					return
				}
				host := &hosts[hi]
				svc := &host.Services[si]
				useTLS := svc.Port == 443 || svc.Port == 8443 || svc.Port == 9443 ||
					(svc.ServiceName != nil && (strings.Contains(strings.ToLower(*svc.ServiceName), "https") || strings.Contains(strings.ToLower(*svc.ServiceName), "ssl")))

				sniHost := ""
				if host.Hostname != nil {
					trimmed := strings.TrimSpace(*host.Hostname)
					if trimmed != "" && net.ParseIP(trimmed) == nil {
						sniHost = trimmed
					}
				}

				fp, body := httpfp.Probe(ctx, host.IP, host.Hostname, svc.Port, useTLS, httpTimeout, rateWait)
				if ctx.Err() != nil || fp == nil {
					return
				}

				enrichTechnologiesFromNmap(fp, svc.Product, svc.Banner)
				if svc.Banner == nil {
					if srv, ok := fp.Headers["Server"]; ok && srv != "" {
						srvCopy := srv
						svc.Banner = &srvCopy
					}
				}
				svc.HTTP = fp
				if job.Profile.SignaturesEnabled && len(job.Signatures) > 0 && fp.ProbeError == nil && fp.StatusCode > 0 {
					matches := signatures.Evaluate(ctx, fp, body, job.Signatures, httpTimeout, sniHost, rateWait)
					if ctx.Err() != nil {
						return
					}
					svc.SignatureMatches = matches
					for _, m := range matches {
						ln := strings.ToLower(m.SignatureName)
						if strings.Contains(ln, "admin") || strings.Contains(ln, "login") || strings.Contains(ln, "dashboard") {
							fp.IsAdminPanel = true
							break
						}
					}
				}
			}(wt.hostIdx, wt.svcIdx)
		}

		wg.Wait()
		if ctx.Err() != nil {
			handleWindowAbort(cfg, &result, job.ChunkID)
			return
		}
	}

	result.Status = "completed"
	result.Hosts = hosts
	result.FinishedAt = time.Now().UTC()
	postResult(cfg, result)
}

func handleWindowAbort(cfg config.Config, result *contract.ScanChunkResult, chunkID string) {
	log.Printf("[asi-scanner] window deadline/shutdown hit during HTTP/signatures for chunk=%s -> requeued_window", chunkID)
	result.Status = "requeued_window"
	result.Hosts = []contract.HostResult{}
	result.FinishedAt = time.Now().UTC()
	postResult(cfg, *result)
}

func enrichTechnologiesFromNmap(fp *contract.HTTPFingerprint, product *string, banner *string) {
	combined := ""
	if product != nil {
		combined += *product + " "
	}
	if banner != nil {
		combined += *banner
	}
	combined = strings.TrimSpace(combined)
	if combined == "" {
		return
	}
	lp := strings.ToLower(combined)
	if fp.TechConfidence == nil {
		fp.TechConfidence = map[string]string{}
	}
	existing := make(map[string]string, len(fp.Technologies))
	for _, t := range fp.Technologies {
		existing[strings.ToLower(t)] = t
	}
	addOrUpgrade := func(name string) {
		if orig, ok := existing[strings.ToLower(name)]; ok {
			// Potwierdzenie z drugiego źródła (nmap + HTTP) -> wysoka pewność
			fp.TechConfidence[orig] = "high"
			return
		}
		fp.Technologies = append(fp.Technologies, name)
		existing[strings.ToLower(name)] = name
		fp.TechConfidence[name] = "medium"
	}

	checks := []struct {
		needle string
		tech   string
	}{
		{"nginx", "nginx"},
		{"golang", "Golang"},
		{"apache", "Apache HTTP Server"},
		{"lighttpd", "lighttpd"},
		{"gunicorn", "Gunicorn"},
		{"werkzeug", "Flask / Werkzeug"},
		{"cowboy", "Erlang Cowboy"},
		{"rabbitmq", "RabbitMQ Management"},
		{"gitea", "Gitea"},
		{"traefik", "Traefik"},
		{"toxiproxy", "Toxiproxy"},
		{"hikvision", "Hikvision IP Camera (IoT)"},
		{"dahua", "Dahua IP Camera (IoT)"},
		{"axis", "Axis Network Camera (IoT)"},
		{"mikrotik", "MikroTik RouterOS (IoT)"},
		{"routeros", "MikroTik RouterOS (IoT)"},
		{"ubiquiti", "Ubiquiti / UniFi (IoT)"},
		{"dropbear", "Dropbear SSH (IoT)"},
		{"busybox", "BusyBox Embedded (IoT)"},
		{"goahead", "GoAhead-Webs (IoT)"},
		{"rompager", "Allegro RomPager (IoT)"},
		{"boa", "Boa Embedded HTTP (IoT)"},
		{"synology", "Synology NAS (IoT)"},
		{"qnap", "QNAP NAS (IoT)"},
		{"openwrt", "OpenWrt (IoT)"},
		{"jetdirect", "HP JetDirect Printer (IoT)"},
		{"rtsp", "RTSP Media Stream (IoT)"},
		{"mqtt", "MQTT Broker (IoT)"},
	}
	for _, chk := range checks {
		if strings.Contains(lp, chk.needle) {
			addOrUpgrade(chk.tech)
		}
	}
	sort.Strings(fp.Technologies)
}

func isWebPort(port int, serviceName *string, product *string, banner *string) bool {
	if serviceName != nil {
		sn := strings.ToLower(strings.TrimSpace(*serviceName))
		switch sn {
		case "ssh", "ftp", "smtp", "mysql", "mariadb", "postgresql", "redis", "amqp", "mongodb", "domain", "smb", "microsoft-ds", "ms-wbt-server", "telnet", "imap", "pop3":
			return false
		}
		if strings.Contains(sn, "http") || strings.Contains(sn, "www") {
			return true
		}
	}
	switch port {
	case 80, 81, 443, 3000, 3001, 5000, 8000, 8080, 8081, 8085, 8086, 8088, 8089, 8090, 8443, 8474, 8787, 8888, 9000, 9090, 9443, 15672, 15673:
		return true
	}
	combined := ""
	if product != nil {
		combined += *product + " "
	}
	if banner != nil {
		combined += *banner
	}
	lc := strings.ToLower(combined)
	for _, hint := range []string{"nginx", "apache", "httpd", "gunicorn", "uvicorn", "werkzeug", "traefik", "gitea", "cowboy", "caddy", "iis", "jetty", "tomcat", "golang", "toxiproxy", "http"} {
		if strings.Contains(lc, hint) {
			return true
		}
	}
	return false
}

func postResult(cfg config.Config, result contract.ScanChunkResult) {
	body, err := json.Marshal(result)
	if err != nil {
		log.Printf("[asi-scanner] marshal result error: %v", err)
		return
	}
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodPost, cfg.BackendIngestURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("[asi-scanner] request error: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner-Token", cfg.ScannerInternalToken)

		resp, err := ingestHTTPClient.Do(req)
		if err != nil {
			log.Printf("[asi-scanner] ingest post error (attempt %d/3): %v", attempt, err)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			log.Printf("[asi-scanner] ingest failed chunk=%s status=%s http_code=%d body=%s",
				result.ChunkID, result.Status, resp.StatusCode, strings.TrimSpace(string(respBody)))
		} else {
			log.Printf("[asi-scanner] sent chunk=%s status=%s hosts=%d http_code=%d",
				result.ChunkID, result.Status, len(result.Hosts), resp.StatusCode)
		}
		if resp.StatusCode < 500 {
			return
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}
}
