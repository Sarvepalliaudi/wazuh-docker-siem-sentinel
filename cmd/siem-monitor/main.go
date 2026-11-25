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
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"wazuh-qram-siem/internal/engine"
	"wazuh-qram-siem/internal/web"
)

const (
	defaultAlerts = "samples/wazuh_alerts_sample.json"
	defaultAuth   = "samples/auth_failed_login.log"
	reportPath    = "WAZUH_ALERT_REPORT.md"
	profilePath   = "operator_profile.json"
)

func main() {
	simulate := flag.Bool("simulate", false, "analyze bundled sample alerts and auth logs")
	serve := flag.Bool("serve", false, "serve the read-only dashboard simulator")
	guide := flag.Bool("guide", false, "run the four-stage interactive walkthrough")
	resetLogin := flag.Bool("reset-login", false, "clear the locally saved operator profile")
	alertsPath := flag.String("alerts", defaultAlerts, "path to Wazuh JSON alerts")
	authPath := flag.String("auth-log", defaultAuth, "path to Linux authentication log")
	flag.Parse()

	printBanner()
	if *resetLogin {
		if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
			fatalf("cannot clear operator profile: %v", err)
		}
		fmt.Println("Operator profile cleared.")
		return
	}
	if *guide {
		runGuide()
		return
	}
	if *serve {
		addr := ":" + strings.TrimSpace(os.Getenv("PORT"))
		if addr == ":" {
			addr = ":8080"
		}
		server := web.NewServer(*alertsPath, *authPath, profilePath)
		fmt.Printf("Dashboard simulator listening on http://0.0.0.0%s\n", addr)
		if err := http.ListenAndServe(addr, server.Handler()); err != nil {
			fatalf("web server stopped: %v", err)
		}
		return
	}
	if *simulate {
		profile, err := loadOperatorProfile(profilePath)
		if err != nil {
			fatalf("operator profile: %v", err)
		}
		result, err := engine.AnalyzeFiles(*alertsPath, *authPath)
		if err != nil {
			fatalf("analysis failed: %v", err)
		}
		result.OperatorName = profile.OperatorName
		result.Organization = profile.Organization
		report := engine.RenderReport(result)
		if err := os.WriteFile(reportPath, []byte(report), 0600); err != nil {
			fatalf("cannot write report %q: %v", reportPath, err)
		}
		fmt.Printf("Analyzed %d alerts; detected %d correlated source(s).\n", len(result.Alerts), result.CorrelatedSources)
		fmt.Printf("Hash-chain integrity: %t\nReport: %s\n", engine.VerifyChain(result.Chain), reportPath)
		return
	}
	flag.Usage()
}

type operatorProfile struct {
	OperatorName string `json:"operator_name"`
	Organization string `json:"organization"`
}

func loadOperatorProfile(path string) (operatorProfile, error) {
	content, err := os.ReadFile(path)
	if err == nil {
		var profile operatorProfile
		if err := json.Unmarshal(content, &profile); err != nil {
			return operatorProfile{}, fmt.Errorf("decode %q: %w", path, err)
		}
		profile.OperatorName = strings.TrimSpace(profile.OperatorName)
		profile.Organization = strings.TrimSpace(profile.Organization)
		if profile.OperatorName == "" || profile.Organization == "" {
			return operatorProfile{}, fmt.Errorf("%q must contain both operator_name and organization; clear it with --reset-login to start again", path)
		}
		return profile, nil
	}
	if !os.IsNotExist(err) {
		return operatorProfile{}, fmt.Errorf("read %q: %w", path, err)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Operator name (required): ")
	name, err := reader.ReadString('\n')
	if err != nil && len(name) == 0 {
		return operatorProfile{}, fmt.Errorf("read operator name: %w", err)
	}
	fmt.Print("Organization (required): ")
	organization, orgErr := reader.ReadString('\n')
	if orgErr != nil && len(organization) == 0 {
		return operatorProfile{}, fmt.Errorf("read organization: %w", orgErr)
	}
	profile := operatorProfile{OperatorName: strings.TrimSpace(name), Organization: strings.TrimSpace(organization)}
	if profile.OperatorName == "" || profile.Organization == "" {
		return operatorProfile{}, fmt.Errorf("operator name and organization are both required")
	}
	encoded, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return operatorProfile{}, fmt.Errorf("encode operator profile: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		return operatorProfile{}, fmt.Errorf("save %q: %w", path, err)
	}
	return profile, nil
}

func printBanner() {
	fmt.Println("wazuh-qram-siem | Wazuh Docker SIEM & Quantum-Safe Log Alert Monitor")
	fmt.Println("Software Architect & Creator: Sarvepalli Audi Siva Bhanuvardhan")
	fmt.Println("Proprietary Notice: Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.")
	fmt.Println("University: B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.")
	fmt.Println("Internship: Cybersecurity Virtual Internship — Dev/Craft by Fennark (https://devcraft.fennark.xyz) | Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring")
	fmt.Println("LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/")
	fmt.Println("GitHub: https://github.com/Sarvepalliaudi")
	fmt.Println("Read-only analysis. Session operator identity is never pre-filled.")
}

func runGuide() {
	stages := []string{
		"Stage 1/4 — Wazuh Manager receives events, the Indexer stores searchable alerts, and the Dashboard presents them.",
		"Stage 2/4 — Rule 5710 identifies failed SSH authentication; 5712 represents native brute-force correlation; 100510 correlates repeated failures by source IP.",
		"Stage 3/4 — This simulator links canonical alert records with SHA-512 hashes so edits or reordering are detectable. It does not claim SHA-3 or authenticated signatures.",
		"Stage 4/4 — The synthesizable Verilog counter raises an interrupt at the configured burst threshold and increments a 16-bit alert counter.",
	}
	reader := bufio.NewReader(os.Stdin)
	for _, stage := range stages {
		fmt.Println(stage)
		fmt.Print("Press ENTER to execute stage...")
		if _, err := reader.ReadString('\n'); err != nil {
			fatalf("walkthrough input failed: %v", err)
		}
		fmt.Println("Stage acknowledged.")
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
