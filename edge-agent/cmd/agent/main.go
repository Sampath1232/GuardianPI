// Guardian Pi Edge Agent — Main Entry Point
// Lightweight, cross-platform security agent written in Go.
// Supports: Windows, Linux, macOS, Raspberry Pi, ARM edge devices.
//
// DEFENSIVE ONLY — This agent monitors and reports. It never performs
// unauthorized access, exploitation, or destructive actions.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/guardianpi/edge-agent/internal/collector"
	"github.com/guardianpi/edge-agent/internal/config"
	"github.com/guardianpi/edge-agent/internal/detector"
	"github.com/guardianpi/edge-agent/internal/queue"
	"github.com/guardianpi/edge-agent/internal/transport"

	"go.uber.org/zap"
)

const Version = "2.0.0"

func main() {
	// Parse flags
	serverURL := flag.String("server", "https://localhost:8000", "Guardian Pi server URL")
	apiKey := flag.String("api-key", "", "Agent API key")
	configPath := flag.String("config", "agent.yaml", "Config file path")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Guardian Pi Edge Agent v%s\n", Version)
		os.Exit(0)
	}

	// Initialize structured logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()

	sugar.Infow("Guardian Pi Edge Agent starting",
		"version", Version,
		"server", *serverURL,
	)

	// Load configuration
	cfg := config.LoadConfig(*configPath, *serverURL, *apiKey)

	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize offline queue (survives restarts)
	offlineQueue := queue.NewDiskQueue(cfg.QueueDir, cfg.MaxQueueSizeMB)
	sugar.Infow("Offline queue initialized", "dir", cfg.QueueDir)

	// Initialize transport (mTLS-capable HTTP client)
	client := transport.NewSecureClient(cfg)
	sugar.Info("Secure transport initialized")

	// Register device with server
	deviceID, err := registerDevice(ctx, client, cfg, sugar)
	if err != nil {
		sugar.Warnw("Device registration failed — operating in offline mode", "error", err)
		deviceID = cfg.DeviceID // Use cached ID if available
	} else {
		sugar.Infow("Device registered", "device_id", deviceID)
	}
	cfg.DeviceID = deviceID

	// Start all monitoring goroutines
	var wg sync.WaitGroup
	eventCh := make(chan collector.Event, 500)

	// System telemetry collector (CPU, RAM, disk, uptime)
	wg.Add(1)
	go func() {
		defer wg.Done()
		collector.RunTelemetry(ctx, eventCh, cfg.TelemetryIntervalSec, sugar)
	}()

	// Process monitor (suspicious process detection)
	wg.Add(1)
	go func() {
		defer wg.Done()
		collector.RunProcessMonitor(ctx, eventCh, cfg.ProcessScanIntervalSec, sugar)
	}()

	// File integrity monitor
	wg.Add(1)
	go func() {
		defer wg.Done()
		collector.RunFileIntegrity(ctx, eventCh, cfg.MonitoredPaths, sugar)
	}()

	// Network connection monitor
	wg.Add(1)
	go func() {
		defer wg.Done()
		collector.RunNetworkMonitor(ctx, eventCh, cfg.NetworkScanIntervalSec, sugar)
	}()

	// Detection engine (Sigma-style rules)
	wg.Add(1)
	go func() {
		defer wg.Done()
		detector.RunDetectionEngine(ctx, eventCh, sugar)
	}()

	// Telemetry sender (batches events, sends to server, queues on failure)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runSender(ctx, eventCh, client, offlineQueue, cfg, sugar)
	}()

	// Heartbeat loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		runHeartbeat(ctx, client, cfg, sugar)
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	sugar.Infow("Shutdown signal received", "signal", sig.String())
	cancel()
	wg.Wait()
	sugar.Info("Guardian Pi Edge Agent stopped gracefully")
}

// registerDevice sends device fingerprint to the server
func registerDevice(ctx context.Context, client *transport.SecureClient, cfg *config.AgentConfig, log *zap.SugaredLogger) (string, error) {
	info := collector.GetDeviceInfo()
	info["agent_version"] = Version

	body, _ := json.Marshal(info)
	resp, err := client.Post(ctx, "/api/v1/devices/register", body)
	if err != nil {
		return "", err
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("parse registration response: %w", err)
	}
	return result.ID, nil
}

// runSender batches events and sends them to the server
func runSender(ctx context.Context, eventCh <-chan collector.Event, client *transport.SecureClient, q *queue.DiskQueue, cfg *config.AgentConfig, log *zap.SugaredLogger) {
	ticker := time.NewTicker(time.Duration(cfg.FlushIntervalSec) * time.Second)
	defer ticker.Stop()

	batch := make([]collector.Event, 0, cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			// Flush remaining events to disk queue
			if len(batch) > 0 {
				data, _ := json.Marshal(batch)
				q.Enqueue(data)
				log.Infow("Flushed remaining events to disk queue", "count", len(batch))
			}
			return

		case evt := <-eventCh:
			batch = append(batch, evt)
			if len(batch) >= cfg.BatchSize {
				sendBatch(ctx, client, q, cfg, batch, log)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				sendBatch(ctx, client, q, cfg, batch, log)
				batch = batch[:0]
			}
			// Try to drain offline queue
			drainQueue(ctx, client, q, cfg, log)
		}
	}
}

func sendBatch(ctx context.Context, client *transport.SecureClient, q *queue.DiskQueue, cfg *config.AgentConfig, batch []collector.Event, log *zap.SugaredLogger) {
	payload := map[string]interface{}{
		"device_id":  cfg.DeviceID,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"data":       map[string]interface{}{"events": batch},
	}
	body, _ := json.Marshal(payload)

	_, err := client.Post(ctx, "/api/v1/telemetry/ingest", body)
	if err != nil {
		log.Warnw("Server unreachable — queueing locally", "error", err, "events", len(batch))
		q.Enqueue(body)
	} else {
		log.Debugw("Telemetry sent", "events", len(batch))
	}
}

func drainQueue(ctx context.Context, client *transport.SecureClient, q *queue.DiskQueue, cfg *config.AgentConfig, log *zap.SugaredLogger) {
	for {
		data, ok := q.Dequeue()
		if !ok {
			return
		}
		_, err := client.Post(ctx, "/api/v1/telemetry/ingest", data)
		if err != nil {
			q.Enqueue(data) // Put it back
			return           // Server still down
		}
		log.Debug("Drained queued telemetry batch")
	}
}

// runHeartbeat sends periodic heartbeats
func runHeartbeat(ctx context.Context, client *transport.SecureClient, cfg *config.AgentConfig, log *zap.SugaredLogger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info := collector.GetSystemMetrics()
			body, _ := json.Marshal(info)
			_, err := client.Post(ctx, fmt.Sprintf("/api/v1/devices/%s/heartbeat", cfg.DeviceID), body)
			if err != nil {
				log.Debugw("Heartbeat failed", "error", err)
			}
		}
	}
}
