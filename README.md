<!--
Tool: wazuh-qram-siem
Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.
Software Architect: Sarvepalli Audi Siva Bhanuvardhan
B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.
Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz | Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring
LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/ | GitHub: https://github.com/Sarvepalliaudi
-->
# wazuh-qram-siem

**Wazuh Docker SIEM & Quantum-Safe Log Alert Monitor** — a Wazuh 4.14.10 single-node Docker Compose deployment, dependency-free Go alert correlation and dashboard simulator, SHA-512 tamper-evident alert chain, and synthesizable Verilog failed-login burst counter.

> Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.

## What is included

- `wazuh_docker/`: Wazuh Manager, Indexer, Dashboard, optional local log agent, persistent Docker volumes, custom SSH/privilege-failure rules, and setup instructions.
- `cmd/siem-monitor/` and `internal/`: Go standard-library-only parser, deterministic IP/time-window correlation, SHA-512 chain verification, HTML dashboard simulator, and Markdown report export.
- `hardware/`: synthesizable RTL burst counter and an Icarus Verilog self-checking testbench.
- `samples/`: sample Wazuh alerts and Linux SSH authentication failure records. These are inert fixtures; no remote authentication attempts are made by the simulator.
- `docs/`: user manual.

## Quick start: simulator

Requires Go 1.24 or newer. From this directory:

```sh
go test ./...
go run ./cmd/siem-monitor --simulate
go run ./cmd/siem-monitor --guide
go run ./cmd/siem-monitor --serve
```

The simulator listens on `0.0.0.0:8080` by default, or the `PORT` environment variable. The first CLI simulation prompts for a session operator name and organization; the web form requires both fields and starts blank. No architect identity is prefilled as an operator. The profile is saved locally with restrictive file permissions. Clear it using `go run ./cmd/siem-monitor --reset-login`.

The generated `WAZUH_ALERT_REPORT.md` uses short table cells and retains full alert JSON and defensive response guidance in Section 3. Hash chaining is tamper-evident but not a signature, and does not authenticate the person who produced the chain.

## Wazuh Docker deployment

Read [wazuh_docker/WAZUH_DOCKER_SETUP_GUIDE.md](wazuh_docker/WAZUH_DOCKER_SETUP_GUIDE.md) before deployment. Wazuh Manager/Indexer/Dashboard need a Linux Docker host and certificates. Set strong unique credentials in `wazuh_docker/.env`; never commit that file. Host log collection is optional and uses read-only mounts through the `local-logs` profile.

## Verilog simulation

On a system with Icarus Verilog installed:

```sh
iverilog -g2012 -o siem-login-guard.out hardware/siem_login_guard.v hardware/tb_siem_login_guard.v
vvp siem-login-guard.out
```

## Creator and academic attribution

- **Software Architect & Creator:** Sarvepalli Audi Siva Bhanuvardhan
- **University:** B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India
- **Internship:** Cybersecurity Virtual Internship — Dev/Craft by Fennark ([devcraft.fennark.xyz](https://devcraft.fennark.xyz))
- **Intern ID:** `DEV-CRAFT-BQ2VPH` | **Task 6:** Log Monitoring
- **LinkedIn:** [Audi Siva Bhanuvardhan Sarvepalli](https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/)
- **GitHub:** [Sarvepalliaudi](https://github.com/Sarvepalliaudi)

This software is intended for authorized defensive security monitoring and training. The included defensive-use condition is an additional restriction beyond the standard MIT terms; see [LICENSE](LICENSE).
