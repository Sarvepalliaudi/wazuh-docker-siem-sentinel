# Tool: wazuh-qram-siem
# Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.
# Software Architect: Sarvepalli Audi Siva Bhanuvardhan
# B.Tech CSE (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.
# Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz | Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring
# LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/ | GitHub: https://github.com/Sarvepalliaudi
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/siem-monitor ./cmd/siem-monitor

FROM scratch
COPY --from=build /out/siem-monitor /siem-monitor
COPY samples /samples
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["/siem-monitor", "--serve", "--alerts", "/samples/wazuh_alerts_sample.json", "--auth-log", "/samples/auth_failed_login.log"]
