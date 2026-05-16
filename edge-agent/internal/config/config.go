// Guardian Pi — Agent Configuration
package config

import (
	"os"
	"runtime"
	"strings"
)

// AgentConfig holds all agent runtime configuration
type AgentConfig struct {
	ServerURL             string
	APIKey                string
	DeviceID              string
	QueueDir              string
	MaxQueueSizeMB        int
	TelemetryIntervalSec  int
	ProcessScanIntervalSec int
	NetworkScanIntervalSec int
	FlushIntervalSec      int
	BatchSize             int
	MonitoredPaths        []string
	CACertPath            string // For mTLS CA certificate
	ClientCertPath        string // For mTLS client cert
	ClientKeyPath         string // For mTLS client key
	EnableTLS             bool
}

// LoadConfig builds configuration from file/flags/env
func LoadConfig(path, serverURL, apiKey string) *AgentConfig {
	cfg := &AgentConfig{
		ServerURL:             serverURL,
		APIKey:                apiKey,
		DeviceID:              getEnvOrDefault("GPI_DEVICE_ID", ""),
		QueueDir:              getEnvOrDefault("GPI_QUEUE_DIR", ".guardian_queue"),
		MaxQueueSizeMB:        50,
		TelemetryIntervalSec:  10,
		ProcessScanIntervalSec: 5,
		NetworkScanIntervalSec: 15,
		FlushIntervalSec:      30,
		BatchSize:             50,
		CACertPath:            getEnvOrDefault("GPI_CA_CERT", ""),
		ClientCertPath:        getEnvOrDefault("GPI_CLIENT_CERT", ""),
		ClientKeyPath:         getEnvOrDefault("GPI_CLIENT_KEY", ""),
		EnableTLS:             true,
		MonitoredPaths:        getMonitoredPaths(),
	}
	return cfg
}

// getMonitoredPaths returns OS-specific critical paths for file integrity monitoring
func getMonitoredPaths() []string {
	switch runtime.GOOS {
	case "linux":
		paths := []string{
			"/etc/passwd", "/etc/shadow", "/etc/hosts",
			"/etc/crontab", "/etc/ssh/sshd_config",
			"/etc/sudoers",
		}
		// Raspberry Pi specific
		if _, err := os.Stat("/boot/config.txt"); err == nil {
			paths = append(paths, "/boot/config.txt")
		}
		return paths
	case "darwin":
		return []string{
			"/etc/hosts", "/etc/passwd",
			"/etc/ssh/sshd_config",
		}
	case "windows":
		return []string{
			`C:\Windows\System32\drivers\etc\hosts`,
			`C:\Windows\System32\config\SAM`,
		}
	default:
		return []string{}
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// SuspiciousProcesses — defensive detection list
var SuspiciousProcesses = map[string]string{
	"mimikatz":    "Credential dumping tool",
	"hydra":       "Brute-force attack tool",
	"nmap":        "Network reconnaissance scanner",
	"netcat":      "Network utility (potential backdoor)",
	"nc":          "Netcat variant",
	"john":        "Password cracking tool",
	"hashcat":     "GPU password cracker",
	"meterpreter": "Metasploit payload",
	"cobalt":      "C2 framework indicator",
	"empire":      "Post-exploitation framework",
	"lazagne":     "Credential recovery tool",
	"responder":   "LLMNR/NBT-NS poisoner",
	"crackmapexec":"Network exploitation tool",
	"bloodhound":  "AD enumeration tool",
	"rubeus":      "Kerberos attack tool",
	"powershell -enc": "Encoded PowerShell (potential obfuscation)",
}

// SuspiciousPorts — ports commonly used by malware/C2
var SuspiciousPorts = map[int]string{
	4444:  "Metasploit default",
	5555:  "Common backdoor",
	1337:  "Leet port (malware)",
	31337: "Back Orifice",
	6666:  "IRC backdoor",
	6667:  "IRC C2",
	8888:  "Alternative HTTP (suspicious)",
	9999:  "Common reverse shell",
	12345: "NetBus trojan",
	4443:  "Alternative HTTPS C2",
}

// IsSuspiciousProcess checks if a process name matches known threat tools
func IsSuspiciousProcess(name string) (bool, string) {
	lower := strings.ToLower(name)
	for pattern, desc := range SuspiciousProcesses {
		if strings.Contains(lower, pattern) {
			return true, desc
		}
	}
	return false, ""
}
