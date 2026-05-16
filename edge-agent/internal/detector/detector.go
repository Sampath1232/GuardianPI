// Guardian Pi — Detection Engine (Sigma-style rule matching)
// Defensive detection for: mimikatz, reverse shells, brute force,
// suspicious persistence, debugger attachment, tampering.
package detector

import (
	"context"
	"strings"
	"time"

	"github.com/guardianpi/edge-agent/internal/collector"
	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"
)

// DetectionRule represents a Sigma-style detection rule
type DetectionRule struct {
	ID          string
	Name        string
	Description string
	Severity    string // critical | high | medium | low
	Category    string // malware | intrusion | persistence | evasion | execution
	MitreTactic string
	Technique   string
	Matcher     func(proc *process.Process) bool
}

// builtinRules contains the defensive detection rules
var builtinRules = []DetectionRule{
	{
		ID: "GPI-001", Name: "Mimikatz Detection",
		Description: "Detects mimikatz credential dumping tool",
		Severity: "critical", Category: "credential_access",
		MitreTactic: "Credential Access", Technique: "T1003",
		Matcher: func(p *process.Process) bool {
			name, _ := p.Name()
			cmd, _ := p.Cmdline()
			lower := strings.ToLower(name + " " + cmd)
			return strings.Contains(lower, "mimikatz") ||
				strings.Contains(lower, "sekurlsa") ||
				strings.Contains(lower, "lsadump")
		},
	},
	{
		ID: "GPI-002", Name: "Reverse Shell Detection",
		Description: "Detects common reverse shell patterns",
		Severity: "critical", Category: "execution",
		MitreTactic: "Execution", Technique: "T1059",
		Matcher: func(p *process.Process) bool {
			cmd, _ := p.Cmdline()
			lower := strings.ToLower(cmd)
			return strings.Contains(lower, "/dev/tcp/") ||
				strings.Contains(lower, "bash -i") ||
				(strings.Contains(lower, "nc ") && strings.Contains(lower, "-e")) ||
				strings.Contains(lower, "ncat") && strings.Contains(lower, "--exec") ||
				strings.Contains(lower, "python") && strings.Contains(lower, "socket") && strings.Contains(lower, "subprocess")
		},
	},
	{
		ID: "GPI-003", Name: "Hydra Brute Force",
		Description: "Detects hydra brute-force attack tool",
		Severity: "high", Category: "credential_access",
		MitreTactic: "Credential Access", Technique: "T1110",
		Matcher: func(p *process.Process) bool {
			name, _ := p.Name()
			return strings.Contains(strings.ToLower(name), "hydra")
		},
	},
	{
		ID: "GPI-004", Name: "Suspicious Persistence (Crontab Edit)",
		Description: "Detects processes modifying crontab or scheduled tasks",
		Severity: "high", Category: "persistence",
		MitreTactic: "Persistence", Technique: "T1053",
		Matcher: func(p *process.Process) bool {
			cmd, _ := p.Cmdline()
			lower := strings.ToLower(cmd)
			return strings.Contains(lower, "crontab -e") ||
				strings.Contains(lower, "schtasks /create") ||
				strings.Contains(lower, "at.exe")
		},
	},
	{
		ID: "GPI-005", Name: "Encoded PowerShell Execution",
		Description: "Detects base64-encoded PowerShell commands (obfuscation)",
		Severity: "high", Category: "execution",
		MitreTactic: "Defense Evasion", Technique: "T1027",
		Matcher: func(p *process.Process) bool {
			cmd, _ := p.Cmdline()
			lower := strings.ToLower(cmd)
			return strings.Contains(lower, "powershell") &&
				(strings.Contains(lower, "-enc") ||
					strings.Contains(lower, "-encodedcommand") ||
					strings.Contains(lower, "frombase64"))
		},
	},
	{
		ID: "GPI-006", Name: "Debugger Attachment",
		Description: "Detects debugger tools that may be used for tampering",
		Severity: "medium", Category: "evasion",
		MitreTactic: "Defense Evasion", Technique: "T1622",
		Matcher: func(p *process.Process) bool {
			name, _ := p.Name()
			lower := strings.ToLower(name)
			return lower == "gdb" || lower == "lldb" ||
				lower == "strace" || lower == "ltrace" ||
				lower == "x64dbg.exe" || lower == "ollydbg.exe" ||
				lower == "windbg.exe" || lower == "ida.exe" ||
				lower == "ida64.exe"
		},
	},
	{
		ID: "GPI-007", Name: "Suspicious Child Process",
		Description: "Detects shells spawned from unusual parent processes",
		Severity: "high", Category: "execution",
		MitreTactic: "Execution", Technique: "T1059",
		Matcher: func(p *process.Process) bool {
			name, _ := p.Name()
			lower := strings.ToLower(name)
			if lower != "cmd.exe" && lower != "powershell.exe" &&
				lower != "bash" && lower != "sh" {
				return false
			}
			parent, err := p.Parent()
			if err != nil {
				return false
			}
			parentName, _ := parent.Name()
			parentLower := strings.ToLower(parentName)
			// Shells spawned from web servers or office apps are suspicious
			suspiciousParents := []string{
				"httpd", "nginx", "apache", "iis", "w3wp",
				"winword", "excel", "powerpnt", "outlook",
				"java", "node", "python",
			}
			for _, sp := range suspiciousParents {
				if strings.Contains(parentLower, sp) {
					return true
				}
			}
			return false
		},
	},
	{
		ID: "GPI-008", Name: "Network Reconnaissance",
		Description: "Detects nmap and similar network scanning tools",
		Severity: "medium", Category: "discovery",
		MitreTactic: "Discovery", Technique: "T1046",
		Matcher: func(p *process.Process) bool {
			name, _ := p.Name()
			lower := strings.ToLower(name)
			return lower == "nmap" || lower == "masscan" ||
				lower == "zmap" || lower == "rustscan"
		},
	},
}

// RunDetectionEngine continuously scans processes against detection rules
func RunDetectionEngine(ctx context.Context, ch chan<- collector.Event, log *zap.SugaredLogger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	log.Infow("Detection engine started", "rules", len(builtinRules))

	// Track already-alerted PIDs to avoid duplicates
	alerted := make(map[string]bool) // key: "ruleID-pid"

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
				for _, rule := range builtinRules {
					alertKey := strings.Join([]string{rule.ID, string(rune(p.Pid))}, "-")
					if alerted[alertKey] {
						continue
					}

					if rule.Matcher(p) {
						name, _ := p.Name()
						username, _ := p.Username()
						cmdline, _ := p.Cmdline()

						ch <- collector.Event{
							EventType: "detection",
							Severity:  rule.Severity,
							Title:     rule.Name + ": " + name,
							Details: map[string]interface{}{
								"rule_id":       rule.ID,
								"rule_name":     rule.Name,
								"description":   rule.Description,
								"category":      rule.Category,
								"mitre_tactic":  rule.MitreTactic,
								"mitre_technique": rule.Technique,
								"pid":           p.Pid,
								"process_name":  name,
								"username":      username,
								"cmdline":       cmdline,
							},
							Timestamp: time.Now().UTC().Format(time.RFC3339),
						}

						alerted[alertKey] = true
						log.Warnw("Detection triggered",
							"rule", rule.Name, "process", name, "pid", p.Pid)
					}
				}
			}
		}
	}
}
