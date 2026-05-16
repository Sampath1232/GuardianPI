// Guardian Pi — System Telemetry & Process Monitoring Collectors
package collector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/guardianpi/edge-agent/internal/config"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"
)

// Event represents a telemetry event to be sent to the server
type Event struct {
	EventType string                 `json:"event_type"`
	Severity  string                 `json:"severity"`
	Title     string                 `json:"title"`
	Details   map[string]interface{} `json:"details"`
	Timestamp string                 `json:"timestamp"`
}

func newEvent(eventType, severity, title string, details map[string]interface{}) Event {
	return Event{
		EventType: eventType,
		Severity:  severity,
		Title:     title,
		Details:   details,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// GetDeviceInfo returns device fingerprint for registration
func GetDeviceInfo() map[string]interface{} {
	info, _ := host.Info()
	cpuInfo, _ := cpu.Info()
	memInfo, _ := mem.VirtualMemory()
	diskInfo, _ := disk.Usage("/")
	if runtime.GOOS == "windows" {
		diskInfo, _ = disk.Usage("C:\\")
	}

	cpuModel := "Unknown"
	if len(cpuInfo) > 0 {
		cpuModel = cpuInfo[0].ModelName
	}

	osType := runtime.GOOS
	if osType == "linux" {
		// Check for Raspberry Pi
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "raspberry") {
				osType = "raspberrypi"
			}
		}
	} else if osType == "darwin" {
		osType = "macos"
	}

	return map[string]interface{}{
		"hostname":     info.Hostname,
		"os_type":      osType,
		"os_version":   info.PlatformVersion,
		"architecture": runtime.GOARCH,
		"cpu_model":    cpuModel,
		"cpu_cores":    runtime.NumCPU(),
		"ram_mb":       int(memInfo.Total / 1024 / 1024),
		"storage_gb":   int(diskInfo.Total / 1024 / 1024 / 1024),
		"is_virtual":   info.VirtualizationRole == "guest",
		"is_rooted":    checkRooted(),
	}
}

// GetSystemMetrics returns current resource usage
func GetSystemMetrics() map[string]interface{} {
	cpuPercent, _ := cpu.Percent(500*time.Millisecond, false)
	memInfo, _ := mem.VirtualMemory()
	diskInfo, _ := disk.Usage("/")
	if runtime.GOOS == "windows" {
		diskInfo, _ = disk.Usage("C:\\")
	}
	uptime, _ := host.Uptime()
	conns, _ := net.Connections("inet")
	procs, _ := process.Pids()

	cpuVal := 0.0
	if len(cpuPercent) > 0 {
		cpuVal = cpuPercent[0]
	}

	return map[string]interface{}{
		"cpu_percent":        cpuVal,
		"ram_percent":        memInfo.UsedPercent,
		"disk_percent":       diskInfo.UsedPercent,
		"uptime_seconds":     int(uptime),
		"active_connections": len(conns),
		"process_count":      len(procs),
	}
}

// RunTelemetry emits periodic system metrics
func RunTelemetry(ctx context.Context, ch chan<- Event, intervalSec int, log *zap.SugaredLogger) {
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()
	log.Info("Telemetry collector started")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics := GetSystemMetrics()
			ch <- newEvent("system_metrics", "info", "System telemetry", metrics)

			// Alert on high resource usage
			if cpu, ok := metrics["cpu_percent"].(float64); ok && cpu > 90 {
				ch <- newEvent("resource_alert", "medium",
					fmt.Sprintf("High CPU usage: %.1f%%", cpu), metrics)
			}
			if ram, ok := metrics["ram_percent"].(float64); ok && ram > 95 {
				ch <- newEvent("resource_alert", "high",
					fmt.Sprintf("Critical RAM usage: %.1f%%", ram), metrics)
			}
		}
	}
}

// RunProcessMonitor scans for suspicious processes
func RunProcessMonitor(ctx context.Context, ch chan<- Event, intervalSec int, log *zap.SugaredLogger) {
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()
	log.Info("Process monitor started")

	knownPIDs := make(map[int32]bool)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			procs, err := process.Processes()
			if err != nil {
				continue
			}

			for _, p := range procs {
				name, err := p.Name()
				if err != nil {
					continue
				}

				// Check against suspicious process list
				if isSusp, desc := config.IsSuspiciousProcess(name); isSusp {
					username, _ := p.Username()
					cmdline, _ := p.Cmdline()
					ch <- newEvent("process_alert", "high",
						fmt.Sprintf("Suspicious process: %s", name),
						map[string]interface{}{
							"pid":         p.Pid,
							"name":        name,
							"username":    username,
							"cmdline":     truncate(cmdline, 500),
							"description": desc,
						})
				}

				// Detect new high-connection processes
				if !knownPIDs[p.Pid] {
					knownPIDs[p.Pid] = true
					conns, _ := p.Connections()
					if len(conns) > 20 {
						ch <- newEvent("process_alert", "medium",
							fmt.Sprintf("New process with %d connections: %s", len(conns), name),
							map[string]interface{}{
								"pid":              p.Pid,
								"name":             name,
								"connection_count": len(conns),
							})
					}
				}

				// Detect high CPU single-process (potential crypto-miner)
				cpuPct, _ := p.CPUPercent()
				if cpuPct > 80 {
					ch <- newEvent("process_alert", "medium",
						fmt.Sprintf("High CPU process: %s (%.1f%%)", name, cpuPct),
						map[string]interface{}{
							"pid":         p.Pid,
							"name":        name,
							"cpu_percent": cpuPct,
						})
				}
			}
		}
	}
}

// RunFileIntegrity watches critical files for modifications
func RunFileIntegrity(ctx context.Context, ch chan<- Event, paths []string, log *zap.SugaredLogger) {
	if len(paths) == 0 {
		log.Warn("No paths configured for file integrity monitoring")
		return
	}

	// Build initial baseline
	baseline := make(map[string]string)
	for _, p := range paths {
		if hash, err := hashFile(p); err == nil {
			baseline[p] = hash
		}
	}
	log.Infow("File integrity baseline created", "files", len(baseline))

	// Use fsnotify for real-time watching
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorw("Failed to create file watcher", "error", err)
		return
	}
	defer watcher.Close()

	for _, p := range paths {
		if err := watcher.Add(p); err != nil {
			log.Debugw("Cannot watch file", "path", p, "error", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
				newHash, err := hashFile(event.Name)
				oldHash := baseline[event.Name]

				changeType := "modified"
				if err != nil {
					changeType = "deleted"
				}

				ch <- newEvent("file_integrity", "high",
					fmt.Sprintf("File %s: %s", changeType, event.Name),
					map[string]interface{}{
						"path":          event.Name,
						"change_type":   changeType,
						"previous_hash": oldHash,
						"current_hash":  newHash,
					})

				if err == nil {
					baseline[event.Name] = newHash
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Errorw("File watcher error", "error", err)
		}
	}
}

// RunNetworkMonitor detects suspicious network activity
func RunNetworkMonitor(ctx context.Context, ch chan<- Event, intervalSec int, log *zap.SugaredLogger) {
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()
	log.Info("Network monitor started")

	var prevConnCount int
	knownRemoteIPs := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conns, err := net.Connections("inet")
			if err != nil {
				continue
			}

			// Connection spike detection
			if prevConnCount > 0 && len(conns) > prevConnCount*3 && len(conns) > 50 {
				ch <- newEvent("network_anomaly", "high",
					fmt.Sprintf("Connection spike: %d (was %d)", len(conns), prevConnCount),
					map[string]interface{}{
						"current_count":  len(conns),
						"previous_count": prevConnCount,
					})
			}
			prevConnCount = len(conns)

			newIPs := 0
			for _, conn := range conns {
				if conn.Status != "ESTABLISHED" || conn.Raddr.IP == "" {
					continue
				}

				// Suspicious port check
				if desc, ok := config.SuspiciousPorts[int(conn.Laddr.Port)]; ok {
					ch <- newEvent("network_anomaly", "high",
						fmt.Sprintf("Listening on suspicious port %d", conn.Laddr.Port),
						map[string]interface{}{
							"local_port":  conn.Laddr.Port,
							"remote_ip":   conn.Raddr.IP,
							"description": desc,
						})
				}

				// Track new remote IPs
				if !knownRemoteIPs[conn.Raddr.IP] {
					knownRemoteIPs[conn.Raddr.IP] = true
					newIPs++
				}
			}

			if newIPs > 20 {
				ch <- newEvent("network_anomaly", "medium",
					fmt.Sprintf("Burst of %d new remote connections", newIPs),
					map[string]interface{}{"new_ip_count": newIPs})
			}
		}
	}
}

// ── Helpers ──────────────────────────────────────────────────────

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func checkRooted() bool {
	switch runtime.GOOS {
	case "linux":
		return os.Geteuid() == 0
	case "windows":
		// Check admin via attempting to open a privileged location
		_, err := os.Open(`\\.\PHYSICALDRIVE0`)
		return err == nil
	default:
		return false
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
