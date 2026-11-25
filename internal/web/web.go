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
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"

	"wazuh-qram-siem/internal/engine"
)

type Server struct {
	alertsPath string
	authPath   string
	profile    string
}

type pageData struct {
	Operator     string
	Organization string
	Report       template.HTML
	Error        string
}

type operatorProfile struct {
	OperatorName string `json:"operator_name"`
	Organization string `json:"organization"`
}

var page = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>wazuh-qram-siem | Alert Monitor</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#101820;color:#eef3f8}
header,section{background:#182733;border:1px solid #344957;border-radius:10px;padding:1.2rem;margin:1rem 0}
h1,h2{color:#7dd3fc}label{display:block;margin:.7rem 0 .2rem}input{box-sizing:border-box;width:100%;padding:.7rem;background:#0e1720;color:white;border:1px solid #607989;border-radius:5px}
button{margin-top:1rem;padding:.7rem 1rem;background:#0284c7;color:white;border:0;border-radius:5px;font-weight:bold}
table{width:100%;border-collapse:collapse;display:block;overflow-x:auto}th,td{text-align:left;padding:.6rem;border-bottom:1px solid #344957;white-space:nowrap}
pre{white-space:pre-wrap;overflow-wrap:anywhere}.error{color:#fca5a5}.muted{color:#b4c3ce}
</style></head><body>
<header><h1>wazuh-qram-siem</h1><p>Wazuh Docker SIEM &amp; Quantum-Safe Log Alert Monitor</p>
<p>Software Architect &amp; Creator: Sarvepalli Audi Siva Bhanuvardhan. Read-only sample analysis; no automated blocking.</p>
<p>Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.</p>
<p>B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.</p>
<p>Cybersecurity Virtual Internship — Dev/Craft by Fennark (<a href="https://devcraft.fennark.xyz">https://devcraft.fennark.xyz</a>) | Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring</p>
<p><a href="https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/">LinkedIn</a> | <a href="https://github.com/Sarvepalliaudi">GitHub</a></p>
<p class="muted">Operator attribution is separate from the creator credit. Fields are intentionally blank and required.</p></header>
<section><h2>Operator session</h2>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="/analyze"><label for="operator">Operator name</label><input id="operator" name="operator" required value="{{.Operator}}">
<label for="organization">Organization</label><input id="organization" name="organization" required value="{{.Organization}}">
<button type="submit">Analyze bundled sample</button></form></section>
{{if .Report}}<section><h2>Analysis result</h2>{{.Report}}</section>{{end}}
<footer class="muted">Generated locally. Hash-chain integrity is tamper evidence, not a digital signature.</footer>
</body></html>`))

func NewServer(alertsPath, authPath, profilePath string) *Server {
	return &Server{alertsPath: alertsPath, authPath: authPath, profile: profilePath}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/analyze", s.analyze)
	return mux
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.render(w, pageData{})
}

func (s *Server) analyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}
	profile := operatorProfile{
		OperatorName: strings.TrimSpace(r.FormValue("operator")),
		Organization: strings.TrimSpace(r.FormValue("organization")),
	}
	if profile.OperatorName == "" || profile.Organization == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, pageData{Error: "Operator name and organization are both required."})
		return
	}
	result, err := engine.AnalyzeFiles(s.alertsPath, s.authPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("analysis failed: %v", err), http.StatusInternalServerError)
		return
	}
	result.OperatorName = profile.OperatorName
	result.Organization = profile.Organization
	encoded, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		http.Error(w, "cannot encode operator profile", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(s.profile, encoded, 0600); err != nil {
		http.Error(w, fmt.Sprintf("cannot save operator profile: %v", err), http.StatusInternalServerError)
		return
	}
	report := template.HTML("<p>Operator: " + template.HTMLEscapeString(profile.OperatorName) +
		" | Organization: " + template.HTMLEscapeString(profile.Organization) + "</p><pre>" +
		template.HTMLEscapeString(engine.RenderReport(result)) + "</pre>")
	s.render(w, pageData{Operator: profile.OperatorName, Organization: profile.Organization, Report: report})
}

func (s *Server) render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	if err := page.Execute(w, data); err != nil {
		http.Error(w, "cannot render dashboard", http.StatusInternalServerError)
	}
}
