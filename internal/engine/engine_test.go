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
	"testing"
	"time"
)

func TestSealDetectsAlertMutation(t *testing.T) {
	alerts := []Alert{{Timestamp: "2026-01-01T00:00:00Z", Rule: Rule{ID: "5710"}}}
	chain := Seal(alerts)
	if !VerifyChain(chain) {
		t.Fatal("fresh chain should verify")
	}
	chain[0].Alert.Rule.ID = "100510"
	if VerifyChain(chain) {
		t.Fatal("modified alert must invalidate chain")
	}
}

func TestParseFailedLogin(t *testing.T) {
	event, ok, err := parseFailedLogin("Nov 25 12:00:01 host sshd[12]: Failed password for invalid user admin from 192.168.56.105 port 51422 ssh2")
	if err != nil || !ok {
		t.Fatalf("parseFailedLogin() = (%v, %v, %v)", event, ok, err)
	}
	if event.sourceIP != "192.168.56.105" {
		t.Fatalf("source IP = %q", event.sourceIP)
	}
}

func TestCorrelationUsesSourceAndSixtySecondWindow(t *testing.T) {
	base := loginEvent{timestamp: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC), sourceIP: "192.0.2.10"}
	events := []loginEvent{
		base,
		{timestamp: base.timestamp.Add(15 * time.Second), sourceIP: base.sourceIP},
		{timestamp: base.timestamp.Add(30 * time.Second), sourceIP: base.sourceIP},
		{timestamp: base.timestamp.Add(45 * time.Second), sourceIP: base.sourceIP},
		{timestamp: base.timestamp.Add(60 * time.Second), sourceIP: base.sourceIP},
		{timestamp: base.timestamp.Add(5 * time.Second), sourceIP: "192.0.2.11"},
		{timestamp: base.timestamp.Add(70 * time.Second), sourceIP: "192.0.2.11"},
		{timestamp: base.timestamp.Add(80 * time.Second), sourceIP: "192.0.2.11"},
		{timestamp: base.timestamp.Add(90 * time.Second), sourceIP: "192.0.2.11"},
		{timestamp: base.timestamp.Add(100 * time.Second), sourceIP: "192.0.2.11"},
	}

	correlated := correlatedIPs(events)
	if len(correlated) != 1 || correlated["192.0.2.10"].IsZero() {
		t.Fatalf("unexpected correlated sources: %#v", correlated)
	}
}

func TestBundledSampleAnalysis(t *testing.T) {
	result, err := AnalyzeFiles("../../samples/wazuh_alerts_sample.json", "../../samples/auth_failed_login.log")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Alerts) != 3 || result.CorrelatedSources != 1 {
		t.Fatalf("unexpected sample result: alerts=%d sources=%d", len(result.Alerts), result.CorrelatedSources)
	}
	for _, alert := range result.Alerts {
		if alert.SourceIP != "192.168.56.105" {
			t.Errorf("rule %s source IP = %q", alert.Rule.ID, alert.SourceIP)
		}
	}
	if !VerifyChain(result.Chain) {
		t.Fatal("sample alert chain did not verify")
	}
}
