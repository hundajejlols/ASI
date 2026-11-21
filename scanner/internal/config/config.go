package config

import (
	"os"
	"strconv"
)

type Config struct {
	RedisURL             string
	RedisJobQueue        string
	WorkerID             string
	ChunkWorkers         int
	Concurrency          int
	DefaultRateLimitPPS  int
	HTTPMaxRPS           int
	HTTPTimeoutSec       int
	BackendIngestURL     string
	ScannerInternalToken string
}

func Load() Config {
	defaultWorkerID := "worker-01"
	if hn, err := os.Hostname(); err == nil && hn != "" {
		defaultWorkerID = "worker-" + hn
	}
	chunkWorkers := getEnvInt("SCANNER_CHUNK_WORKERS", 2)
	if chunkWorkers < 1 {
		chunkWorkers = 1
	}
	httpMaxRPS := getEnvInt("SCANNER_HTTP_MAX_RPS", 20)
	if httpMaxRPS < 1 {
		httpMaxRPS = 20
	}
	return Config{
		RedisURL:             getEnv("REDIS_URL", "redis://redis:6379/0"),
		RedisJobQueue:        getEnv("REDIS_JOB_QUEUE", "asi:scan:chunks"),
		WorkerID:             getEnv("SCANNER_WORKER_ID", defaultWorkerID),
		ChunkWorkers:         chunkWorkers,
		Concurrency:          getEnvInt("SCANNER_CONCURRENCY", 4),
		DefaultRateLimitPPS:  getEnvInt("SCANNER_RATE_LIMIT_PPS", 300),
		HTTPMaxRPS:           httpMaxRPS,
		HTTPTimeoutSec:       getEnvInt("SCANNER_HTTP_TIMEOUT_SEC", 5),
		BackendIngestURL:     getEnv("BACKEND_INGEST_URL", "http://backend:8000/api/v1/scans/ingest"),
		ScannerInternalToken: getEnv("SCANNER_INTERNAL_TOKEN", "changeme_internal_scanner_token"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return fallback
}
