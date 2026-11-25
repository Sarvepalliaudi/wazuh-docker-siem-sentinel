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
package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorFieldsRequiredAndEscaped(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "operator_profile.json")
	server := NewServer("../../samples/wazuh_alerts_sample.json", "../../samples/auth_failed_login.log", profile)

	missing := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("operator=&organization="))
	missing.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusBadRequest {
		t.Fatalf("empty profile status = %d, want %d", missingResponse.Code, http.StatusBadRequest)
	}

	request := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("operator=%3Coperator%3E&organization=Lab"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid profile status = %d, body: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "<operator>") || !strings.Contains(response.Body.String(), "&lt;operator&gt;") {
		t.Fatal("operator-supplied markup was not escaped")
	}
	if _, err := os.Stat(profile); err != nil {
		t.Fatalf("operator profile was not saved: %v", err)
	}
}
