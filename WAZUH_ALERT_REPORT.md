# Wazuh Alert Analysis Report

Tool: wazuh-qram-siem — Wazuh Docker SIEM & Quantum-Safe Log Alert Monitor  
Software Architect & Creator: Sarvepalli Audi Siva Bhanuvardhan  
Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.

**University:** B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.  
**Internship:** Cybersecurity Virtual Internship — Dev/Craft by Fennark (https://devcraft.fennark.xyz) | Intern ID: DEV-CRAFT-BQ2VPH | Task 6: Log Monitoring.  
**LinkedIn:** https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/ | **GitHub:** https://github.com/Sarvepalliaudi

## 1. Summary

- Parsed alerts: 3
- Correlated source IPs: 1
- Correlation window: 60 seconds; threshold: 5 failed logins
- SHA-512 chain valid: true
- Operator: not recorded by the simulator

## 2. Alert Table

| Time (UTC) | Rule | Level | Source IP | Summary |
|---|---:|---:|---|---|
| 2026-11-25T06:40:01.000Z | 5710 | 5 |  | sshd: authentication failed. |
| 2026-11-25T06:40:40.000Z | 5712 | 10 |  | sshd: brute force trying to get access to the system. |
| 2026-11-25T12:40:29Z | 100510 | 10 | 192.168.56.105 | Repeated authentication failures from one source IP |

## 3. Full Alert Data and Remediation

### Alert 1 — Rule 5710

```json
{
  "timestamp": "2026-11-25T06:40:01.000Z",
  "rule": {
    "id": "5710",
    "level": 5,
    "description": "sshd: authentication failed.",
    "groups": [
      "authentication_failed",
      "invalid_login",
      "sshd"
    ],
    "mitre": {}
  },
  "agent": {
    "id": "001",
    "name": "local-log-agent"
  },
  "manager": {
    "name": "wazuh.manager"
  },
  "data": {
    "dstuser": "admin",
    "srcip": "192.168.56.105"
  }
}
```

**Suggested defensive response:** Confirm the source and account with the system owner, review adjacent authentication and privilege events, apply approved rate-limiting or account-protection controls, and preserve the original logs. Do not block addresses automatically based on this simulator.

### Alert 2 — Rule 5712

```json
{
  "timestamp": "2026-11-25T06:40:40.000Z",
  "rule": {
    "id": "5712",
    "level": 10,
    "description": "sshd: brute force trying to get access to the system.",
    "groups": [
      "authentication_failed",
      "sshd"
    ],
    "mitre": {
      "id": [
        "T1110"
      ]
    }
  },
  "agent": {
    "id": "001",
    "name": "local-log-agent"
  },
  "manager": {
    "name": "wazuh.manager"
  },
  "data": {
    "dstuser": "admin",
    "srcip": "192.168.56.105"
  }
}
```

**Suggested defensive response:** Confirm the source and account with the system owner, review adjacent authentication and privilege events, apply approved rate-limiting or account-protection controls, and preserve the original logs. Do not block addresses automatically based on this simulator.

### Alert 3 — Rule 100510

```json
{
  "timestamp": "2026-11-25T12:40:29Z",
  "rule": {
    "id": "100510",
    "level": 10,
    "description": "Repeated authentication failures from one source IP",
    "groups": [
      "authentication_failed",
      "local_correlation"
    ],
    "mitre": {
      "id": [
        "T1110"
      ]
    }
  },
  "agent": {
    "name": "local-log-simulator"
  },
  "manager": {
    "name": "wazuh-qram-siem"
  },
  "source_ip": "192.168.56.105"
}
```

**Suggested defensive response:** Confirm the source and account with the system owner, review adjacent authentication and privilege events, apply approved rate-limiting or account-protection controls, and preserve the original logs. Do not block addresses automatically based on this simulator.

## 4. Tamper-Evident Chain

| Entry | Previous SHA-512 | Alert SHA-512 |
|---:|---|---|
| 1 | `00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` | `bbcd6513570e7486f0466c1546c9d31c2e9e3f7ee80b64452ec2ad88d81186ef147c8bd3945f264b4c2e570448178f5d2c77a127423691abd32cb780d96ed1d9` |
| 2 | `bbcd6513570e7486f0466c1546c9d31c2e9e3f7ee80b64452ec2ad88d81186ef147c8bd3945f264b4c2e570448178f5d2c77a127423691abd32cb780d96ed1d9` | `7027ab8efeb64e875ca380780f8498c841798017ed7d981413a735df45d92a708873916b9db02f6006b842e82afb2d241434ed7ed25e0046c229100a094feb2e` |
| 3 | `7027ab8efeb64e875ca380780f8498c841798017ed7d981413a735df45d92a708873916b9db02f6006b842e82afb2d241434ed7ed25e0046c229100a094feb2e` | `07521a321f5182deb72810c919b53f411c4afaa5053725eae27c004c2f3c363616b5b1ddf14acb44b59c91e927f4c9d77cba649d1c059039ee1cf3d77c4b3d8a` |

SHA-512 hash chaining provides tamper evidence, not a digital signature or proof against an editor who can recompute the entire chain. No operator credentials are included.
