/*
Tool: wazuh-qram-siem
Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.
Software Architect: Sarvepalli Audi Siva Bhanuvardhan
B.Tech CSE (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University,
Tiruchirappalli, Tamil Nadu, India.
Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz
Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring
LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
GitHub: https://github.com/Sarvepalliaudi
*/
package engine

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const burstThreshold = 5
const burstWindow = 60 * time.Second

type Alert struct {
	Timestamp string         `json:"timestamp"`
	Rule      Rule           `json:"rule"`
	Agent     Agent          `json:"agent"`
	Manager   ManagerInfo    `json:"manager,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
	SourceIP  string         `json:"source_ip,omitempty"`
}

type Rule struct {
	ID          string   `json:"id"`
	Level       int      `json:"level"`
	Description string   `json:"description"`
	Groups      []string `json:"groups,omitempty"`
	MITRE       MITRE    `json:"mitre,omitempty"`
}

type MITRE struct {
	ID []string `json:"id,omitempty"`
}

type Agent struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ManagerInfo struct {
	Name string `json:"name,omitempty"`
}

type ChainEntry struct {
	Previous string `json:"previous"`
	Hash     string `json:"hash"`
	Alert    Alert  `json:"alert"`
}

type Result struct {
	Alerts            []Alert
	Chain             []ChainEntry
	CorrelatedSources int
	WindowSeconds     int
	Threshold         int
	OperatorName      string
	Organization      string
}

type alertEnvelope struct {
	Alerts []Alert `json:"alerts"`
}

type loginEvent struct {
	timestamp time.Time
	sourceIP  string
}

func AnalyzeFiles(alertPath, authPath string) (Result, error) {
	alerts, err := LoadAlerts(alertPath)
	if err != nil {
		return Result{}, err
	}
	logEvents, err := loadLoginEvents(authPath)
	if err != nil {
		return Result{}, err
	}
	correlated := correlatedIPs(logEvents)
	for _, ip := range sortedSourceIPs(correlated) {
		alerts = append(alerts, Alert{
			Timestamp: correlated[ip].UTC().Format(time.RFC3339),
			Rule: Rule{
				ID:          "100510",
				Level:       10,
				Description: "Repeated authentication failures from one source IP",
				Groups:      []string{"authentication_failed", "local_correlation"},
				MITRE:       MITRE{ID: []string{"T1110"}},
			},
			Agent:    Agent{Name: "local-log-simulator"},
			Manager:  ManagerInfo{Name: "wazuh-qram-siem"},
			SourceIP: ip,
		})
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		if alerts[i].Timestamp == alerts[j].Timestamp {
			return alerts[i].Rule.ID < alerts[j].Rule.ID
		}
		return alerts[i].Timestamp < alerts[j].Timestamp
	})
	return Result{
		Alerts:            alerts,
		Chain:             Seal(alerts),
		CorrelatedSources: len(correlated),
		WindowSeconds:     int(burstWindow.Seconds()),
		Threshold:         burstThreshold,
	}, nil
}

func LoadAlerts(path string) ([]Alert, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read alerts %q: %w", path, err)
	}
	var envelope alertEnvelope
	if err := json.Unmarshal(content, &envelope); err == nil && envelope.Alerts != nil {
		return withSourceIPs(envelope.Alerts), nil
	}
	var alerts []Alert
	if err := json.Unmarshal(content, &alerts); err == nil {
		return withSourceIPs(alerts), nil
	}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var alert Alert
		if err := json.Unmarshal([]byte(line), &alert); err != nil {
			return nil, fmt.Errorf("parse alert JSON line %d: %w", lineNo, err)
		}
		alerts = append(alerts, alert)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan alerts %q: %w", path, err)
	}
	if alerts == nil {
		return nil, fmt.Errorf("no alerts found in %q", path)
	}
	return withSourceIPs(alerts), nil
}

func withSourceIPs(alerts []Alert) []Alert {
	for i := range alerts {
		if alerts[i].SourceIP == "" && alerts[i].Data != nil {
			if sourceIP, ok := alerts[i].Data["srcip"].(string); ok {
				alerts[i].SourceIP = sourceIP
			}
		}
	}
	return alerts
}

func loadLoginEvents(path string) ([]loginEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open auth log %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var events []loginEvent
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		event, ok, err := parseFailedLogin(line)
		if err != nil {
			return nil, fmt.Errorf("parse auth log line %d: %w", lineNo, err)
		}
		if ok {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan auth log %q: %w", path, err)
	}
	return events, nil
}

func parseFailedLogin(line string) (loginEvent, bool, error) {
	const marker = " Failed password for "
	index := strings.Index(line, marker)
	if index < 0 {
		return loginEvent{}, false, nil
	}
	rest := line[index+len(marker):]
	fromIndex := strings.Index(rest, " from ")
	if fromIndex < 0 {
		return loginEvent{}, false, fmt.Errorf("failed-password record is missing source address")
	}
	sourceParts := strings.Fields(rest[fromIndex+len(" from "):])
	if len(sourceParts) < 3 || sourceParts[1] != "port" {
		return loginEvent{}, false, fmt.Errorf("failed-password record has malformed source address/port")
	}
	if net.ParseIP(sourceParts[0]) == nil {
		return loginEvent{}, false, fmt.Errorf("invalid source IP %q", sourceParts[0])
	}
	port, err := strconv.Atoi(sourceParts[2])
	if err != nil || port < 0 || port > 65535 {
		return loginEvent{}, false, fmt.Errorf("invalid source port %q", sourceParts[2])
	}
	timeFields := strings.Fields(strings.TrimSpace(line[:index]))
	if len(timeFields) < 3 {
		return loginEvent{}, false, fmt.Errorf("failed-password record is missing a syslog timestamp")
	}
	timestamp, err := time.Parse("Jan _2 15:04:05", strings.Join(timeFields[:3], " "))
	if err != nil {
		return loginEvent{}, false, fmt.Errorf("invalid syslog timestamp: %w", err)
	}
	year := time.Now().UTC().Year()
	timestamp = time.Date(year, timestamp.Month(), timestamp.Day(), timestamp.Hour(), timestamp.Minute(), timestamp.Second(), 0, time.UTC)
	return loginEvent{timestamp: timestamp, sourceIP: sourceParts[0]}, true, nil
}

func correlatedIPs(events []loginEvent) map[string]time.Time {
	byIP := make(map[string][]time.Time)
	for _, event := range events {
		byIP[event.sourceIP] = append(byIP[event.sourceIP], event.timestamp)
	}
	result := make(map[string]time.Time)
	for ip, timestamps := range byIP {
		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i].Before(timestamps[j]) })
		for end := range timestamps {
			start := end
			for start > 0 && timestamps[end].Sub(timestamps[start-1]) <= burstWindow {
				start--
			}
			if end-start+1 >= burstThreshold {
				result[ip] = timestamps[end]
				break
			}
		}
	}
	return result
}

func Seal(alerts []Alert) []ChainEntry {
	entries := make([]ChainEntry, 0, len(alerts))
	previous := strings.Repeat("0", sha512.Size*2)
	for _, alert := range alerts {
		payload, _ := json.Marshal(alert)
		digest := sha512.Sum512([]byte(previous + "|" + string(payload)))
		hash := hex.EncodeToString(digest[:])
		entries = append(entries, ChainEntry{Previous: previous, Hash: hash, Alert: alert})
		previous = hash
	}
	return entries
}

func VerifyChain(entries []ChainEntry) bool {
	previous := strings.Repeat("0", sha512.Size*2)
	for _, entry := range entries {
		if entry.Previous != previous {
			return false
		}
		payload, err := json.Marshal(entry.Alert)
		if err != nil {
			return false
		}
		digest := sha512.Sum512([]byte(previous + "|" + string(payload)))
		expected := hex.EncodeToString(digest[:])
		if entry.Hash != expected {
			return false
		}
		previous = entry.Hash
	}
	return true
}

func RenderReport(result Result) string {
	var out strings.Builder
	out.WriteString("# Wazuh Alert Analysis Report\n\n")
	out.WriteString("Tool: wazuh-qram-siem — Wazuh Docker SIEM & Quantum-Safe Log Alert Monitor  \n")
	out.WriteString("Software Architect & Creator: Sarvepalli Audi Siva Bhanuvardhan  \n")
	out.WriteString("Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.\n\n")
	out.WriteString("**University:** B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.  \n")
	out.WriteString("**Internship:** Cybersecurity Virtual Internship — Dev/Craft by Fennark (https://devcraft.fennark.xyz) | Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring.  \n")
	out.WriteString("**LinkedIn:** https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/ | **GitHub:** https://github.com/Sarvepalliaudi\n\n")
	out.WriteString("## 1. Summary\n\n")
	fmt.Fprintf(&out, "- Parsed alerts: %d\n- Correlated source IPs: %d\n- Correlation window: %d seconds; threshold: %d failed logins\n- SHA-512 chain valid: %t\n\n", len(result.Alerts), result.CorrelatedSources, result.WindowSeconds, result.Threshold, VerifyChain(result.Chain))
	out.WriteString("## Operator Attribution\n\n")
	if result.OperatorName == "" || result.Organization == "" {
		out.WriteString("Operator: not recorded\n\n")
	} else {
		fmt.Fprintf(&out, "**Operator:** %s | **Organization:** %s\n\n", cell(result.OperatorName), cell(result.Organization))
	}
	out.WriteString("## 2. Alert Table\n\n| Time (UTC) | Rule | Level | Source IP | Summary |\n|---|---:|---:|---|---|\n")
	for _, alert := range result.Alerts {
		fmt.Fprintf(&out, "| %s | %s | %d | %s | %s |\n",
			cell(alert.Timestamp), cell(alert.Rule.ID), alert.Rule.Level, cell(alert.SourceIP), cell(alert.Rule.Description))
	}
	out.WriteString("\n## 3. Full Alert Data and Remediation\n\n")
	for index, alert := range result.Alerts {
		encoded, err := json.MarshalIndent(alert, "", "  ")
		if err != nil {
			encoded = []byte(`{"error":"alert serialization failed"}`)
		}
		fmt.Fprintf(&out, "### Alert %d — Rule %s\n\n```json\n%s\n```\n\n", index+1, alert.Rule.ID, encoded)
		out.WriteString("**Suggested defensive response:** Confirm the source and account with the system owner, review adjacent authentication and privilege events, apply approved rate-limiting or account-protection controls, and preserve the original logs. Do not block addresses automatically based on this simulator.\n\n")
	}
	out.WriteString("## 4. Tamper-Evident Chain\n\n")
	out.WriteString("| Entry | Previous SHA-512 | Alert SHA-512 |\n|---:|---|---|\n")
	for i, entry := range result.Chain {
		fmt.Fprintf(&out, "| %d | `%s` | `%s` |\n", i+1, entry.Previous, entry.Hash)
	}
	out.WriteString("\nSHA-512 hash chaining provides tamper evidence, not a digital signature or proof against an editor who can recompute the entire chain. No operator credentials are included.\n")
	return out.String()
}

func cell(value string) string {
	value = strings.NewReplacer("|", "\\|", "\r", " ", "\n", " ", "`", "'").Replace(value)
	if len(value) > 88 {
		value = value[:85] + "..."
	}
	return value
}

func sortedSourceIPs(values map[string]time.Time) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
