<!--
Tool: wazuh-qram-siem
Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.
Software Architect: Sarvepalli Audi Siva Bhanuvardhan
B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.
Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz | Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring
LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/ | GitHub: https://github.com/Sarvepalliaudi
-->
# User Manual — wazuh-qram-siem

**Wazuh Docker SIEM & Quantum-Safe Log Alert Monitor**

> Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.

## Attribution and operator identity

The software architect and creator is Sarvepalli Audi Siva Bhanuvardhan. That attribution is not a default operator identity. The optional web session form starts blank and requires both an operator name and organization. A submitted profile is saved to `operator_profile.json`; delete it with `go run ./cmd/siem-monitor --reset-login`. Keep that local file private. The simulator does not use it to authenticate users or authorize system access.

## Go alert simulator

Use Go 1.24+ and run from the project root:

```sh
go test ./...
go run ./cmd/siem-monitor --simulate
go run ./cmd/siem-monitor --serve
```

`--simulate` prompts for required operator name and organization on first run, reads the included JSON and syslog fixtures without modifying them, correlates at least five failures from one source IP within 60 seconds, and writes `WAZUH_ALERT_REPORT.md`. `--alerts` and `--auth-log` accept alternate file paths. JSON may be an `alerts` envelope, a JSON array, or JSON Lines. Malformed input is reported as an error.

`--serve` opens an HTTP dashboard simulator on `0.0.0.0:8080`; set `PORT` to change the port. The free Render service uses the same simulator and bundled fixtures, not a hosted Wazuh cluster. Do not expose this demo publicly with sensitive log input. Use TLS and an access-control layer before deployment for real operational use.

`--guide` is a four-stage interactive walkthrough. Press Enter at each prompt to proceed. `--reset-login` clears only `operator_profile.json` in the current directory.

## Integrity model

Each alert is serialized deterministically and linked to the preceding SHA-512 digest. The chain is checked in memory and reported. This detects edits against a separately retained trusted digest, but by itself does not prevent an attacker with write access from rebuilding the chain. It is not a signed audit log. SHA-3 is not claimed or used.

## Docker Wazuh stack

See [WAZUH_DOCKER_SETUP_GUIDE.md](../wazuh_docker/WAZUH_DOCKER_SETUP_GUIDE.md). Do not use default credentials in a real environment. The Compose stack requires TLS certificates from the Wazuh certificate generator. Persistent volumes hold manager/indexer data. The optional local agent reads mounted host logs in read-only mode.

## Hardware simulation

Install Icarus Verilog, then run:

```sh
iverilog -g2012 -o siem-login-guard.out hardware/siem_login_guard.v hardware/tb_siem_login_guard.v
vvp siem-login-guard.out
```

The RTL is a clock-window demonstration counter. It does not receive network traffic or identify remote addresses. Adapt and verify timing parameters for the intended FPGA or ASIC target.

## Academic and internship credentials

- **University:** B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India
- **Internship:** Cybersecurity Virtual Internship — Dev/Craft by Fennark ([https://devcraft.fennark.xyz](https://devcraft.fennark.xyz))
- **Intern ID:** `DEV-CRAFT-BQ2VPH` | **Task 6:** Log Monitoring
- **LinkedIn:** [https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/](https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/)
- **GitHub:** [https://github.com/Sarvepalliaudi](https://github.com/Sarvepalliaudi)

Software is provided for authorized defensive monitoring and training only. See the project `LICENSE`.
