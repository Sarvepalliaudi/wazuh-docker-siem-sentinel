<!--
Tool: wazuh-qram-siem
Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.
Software Architect: Sarvepalli Audi Siva Bhanuvardhan
B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.
Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz | Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring
LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/ | GitHub: https://github.com/Sarvepalliaudi
-->
# Wazuh Docker 4.14.10 Setup Guide

> Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.

## Requirements and host preparation

Use a supported Linux Docker host with Docker Compose v2 and enough memory for the Manager, Indexer, and Dashboard. On the host, raise the OpenSearch virtual-memory map limit before starting:

```sh
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh-indexer.conf
```

The Wazuh Indexer is memory-intensive; a free-tier web container is not suitable for this stack. The Render configuration in the repository hosts only the lightweight Go simulator.

## Certificates and secrets

Run commands from this `wazuh_docker/` directory. This project includes `generate-indexer-certs.yml` and `config/certs.yml`, configured for the Wazuh certificate generator image and the manager, indexer, and dashboard nodes. Keep generated private keys out of version control. Generate certificates:

```text
root-ca.pem
wazuh.manager.pem          wazuh.manager-key.pem
wazuh.indexer.pem          wazuh.indexer-key.pem
wazuh.dashboard.pem        wazuh.dashboard-key.pem
admin.pem                  admin-key.pem
```

Use the official generator's release-matched instructions, typically:

```sh
docker compose -f generate-indexer-certs.yml run --rm generator
```

The output is written to `config/wazuh_indexer_ssl_certs/`. Copy the matching node certificates and private keys plus the root CA and admin certificate/key into `config/` using the names referenced by the main Compose file. Verify the exact filenames in the generated directory before starting the deployment.

Create a local `.env` file (never commit it) containing strong, unique values:

```dotenv
INDEXER_USERNAME=admin
INDEXER_PASSWORD=replace-with-a-long-random-secret
API_USERNAME=wazuh-wui
API_PASSWORD=replace-with-another-long-random-secret
# Optional host paths; both are mounted read-only into the local agent.
HOST_AUTH_LOG=/var/log/auth.log
HOST_SYSLOG=/var/log/syslog
```

The host log paths vary by distribution; for example, some use `/var/log/secure` instead of `/var/log/auth.log`. Set paths to existing files. The Compose `local-logs` profile runs a dedicated agent configured for syslog input. Enable it only when host log collection is intended:

```sh
docker compose --profile local-logs up -d
```

Without that profile, start the single-node core:

```sh
docker compose up -d
docker compose ps
docker compose logs --tail=100 wazuh.manager wazuh.indexer wazuh.dashboard
```

The manager has ports `1514/tcp` (agent events), `1515/tcp` (enrollment), and `55000/tcp` (API); the Indexer is on `9200/tcp`; the Dashboard is exposed on host port `443` (`https://localhost:443`). Restrict these ports with host firewall rules and never publish administrative APIs to the public Internet.

## Verify the dashboard and rules

Open [https://localhost:443](https://localhost:443), accept the locally generated certificate warning only in this isolated lab, and sign in using the credentials and password initialization required by the official image release.

To safely generate failed SSH attempts locally, use a local test target only. Start a disposable SSH server container on loopback and direct test attempts to that container; do not use public addresses or third-party hosts. For example, with an authorized local SSH test service listening on `127.0.0.1:2222`:

```sh
for attempt in 1 2 3 4 5; do
  ssh -p 2222 -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 -o ConnectTimeout=2 invaliduser@127.0.0.1
done
```

Inspect **Threat Hunting / Security Events** using:

```text
rule.id:(5710 OR 5712 OR 100510)
```

Rule `5710` represents failed SSH authentication, `5712` the built-in brute-force correlation, and custom `100510` correlates repeated `authentication_failed` events by source IP over 60 seconds (including matching event groups from SSH/system login decoders). Custom `100511` identifies a burst of sudo/root escalation failures and maps it to ATT&CK `T1548`. Confirm that the relevant built-in events carry the expected `authentication_failed` or `sudo_failed` groups in your exact Wazuh rule set before relying on these local rules.

## Stop and reset

```sh
docker compose down
```

`docker compose down -v` also deletes persistent Indexer and Manager data; run it only when intentionally resetting the lab. Back up certificates and data securely. Review `docker compose config` before deployment to catch missing certificate files or unset secrets.
