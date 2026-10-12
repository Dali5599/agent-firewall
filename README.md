<p align="center">
  <img src="./assets/banner.svg" alt="Project Banner" width="100%">
</p>

<div align="center">

# 🦈 AGENT FIREWALL
### Sovereign Security & Observability Proxy for Autonomous AI Agents

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](https://www.docker.com/)
[![Tailwind CSS](https://img.shields.io/badge/tailwind-css-38B2AC.svg)](https://tailwindcss.com/)
[![SQLite WAL](https://img.shields.io/badge/sqlite-wal-003B57.svg)](https://www.sqlite.org/)

*Enterprise-grade local security proxy intercepting OpenAI and Anthropic API traffic with real-time secret redaction, hard token budget circuit breakers, and sovereign audit logging.*

</div>

---

## ⚡ Overview

Autonomous AI agents write code, execute bash commands, query databases, and call APIs autonomously. This velocity introduces catastrophic security vectors: accidental API key leaks, infinite-loop token drain, and destructive system commands (`rm -rf /`).

**Agent Firewall** sits invisibly between your autonomous agents (LangChain, AutoGen, CrewAI, custom loops) and upstream LLM providers (OpenAI, Anthropic). It inspects every payload in real-time, enforcing security policies, redacting secrets, limiting token consumption, and maintaining an immutable SQLite audit trail—all wrapped in a cyberpunk tactical web dashboard.

```
+------------------+     +------------------------     +------------------+
|  Autonomous Agent| --> |      AGENT FIREWALL         | --> |  OpenAI / Anthropic|
| (LangChain/Crew) |     | (Intercept / Inspect / Redact)|   |  API Provider    |
+------------------+     +-----------------------------+   +------------------+
                                        |
                                 [ SQLite WAL Log ]
                                        |
                                 [ Cyberpunk UI ]
```

---

## 🚀 Key Features

* **Real-Time Secret Redaction:** Regex and entropy-based scanning intercepts AWS keys, SSH keys, GitHub tokens, JWTs, and database URIs before they leave your perimeter.
* **Hard Token Budget Circuit Breakers:** Prevent runaway loops. Set per-session or global dollar/token limits that immediately sever the connection when exceeded.
* **Destructive Bash Command Blocking:** Inspects tool use arguments (e.g., in JSON tool calls) to block `rm -rf`, `DROP DATABASE`, `sudo`, and fork bombs.
* **Sovereign SQLite WAL Audit Logs:** High-concurrency, zero-config local storage for complete request/response telemetry and forensic analysis.
* **Cyberpunk Tailwind Web Dashboard:** Real-time metrics, live log stream, circuit breaker controls, and threat inspection powered by Tailwind CSS.
* **Robust CLI:** Simple commands to spin up the proxy, run test suites, check token budgets, and view live logs.

---

## 🛠️ Installation

### Prerequisites

* Python 3.11+
* Docker & Docker Compose (optional, for containerized deployment)

### Local Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/agent-firewall.git
   cd agent-firewall
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your upstream provider keys and firewall settings
   ```

---

## 📦 Containerization (Docker)

Deploy Agent Firewall instantly as a sovereign sidecar container next to your agent workers.

1. **Build the container image:**
   ```bash
   docker build -t agent-firewall:latest .
   ```

2. **Run via Docker Compose:**
   ```bash
   docker-compose up -d
   ```

The proxy will be accessible at `http://localhost:8080`, with the dashboard running on `http://localhost:8080/dashboard`.

---

## 💻 Usage

### 1. Starting the Proxy CLI

Start the firewall server using the built-in CLI:

```bash
python -m agent_firewall.cli start --host 0.0.0.0 --port 8080
```

### 2. Pointing Your Agent to the Firewall

Instead of making direct calls to OpenAI or Anthropic, point your SDK base URL to Agent Firewall:

#### OpenAI Python SDK Example:
```python
from openai import OpenAI

client = OpenAI(
    api_key="your-openai-api-key",
    base_url="http://localhost:8080/v1" # Point to Agent Firewall
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Execute a script using my AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}]
)

print(response.choices[0].message.content)
```

#### Anthropic Python SDK Example:
```python
import anthropic

client = anthropic.Anthropic(
    api_key="your-anthropic-api-key",
    base_url="http://localhost:8080" # Point to Agent Firewall
)

response = client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=1000,
    messages=[{"role": "user", "content": "Hello, secure world!"}]
)

print(response.content)
```

---

## 📊 Cyberpunk Web Dashboard

Access the real-time telemetry dashboard at `http://localhost:8080/dashboard`.

* **Live Threat Feed:** Watch intercepted secrets and blocked bash commands flash in real-time.
* **Token Budget Gauges:** Visual burn-down charts of your hard token limits.
* **Audit Inspector:** Deep-dive into raw request/response payloads stored securely in SQLite WAL.

---

## ⚙️ Configuration

Configure thresholds, redaction regexes, and circuit breaker limits in `config.yaml` or via environment variables:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
security:
  redact_secrets: true
  block_destructive_commands: true
  max_tokens_per_session: 50000
  budget_limit_usd: 10.00
database:
  path: "sqlite:///firewall_audit.db"
```

---

## 🛡️ Architecture & Security

* **Zero-Trust Interception:** All upstream traffic is parsed, validated, scrubbed, and audited synchronously.
* **WAL Mode SQLite:** Guarantees durability and high-throughput concurrent reads/writes without locking your agent loops.
* **In-Memory Token Cache:** Fast O(1) token usage tracking across distributed agent threads.

---

## 🤝 Contributing

We welcome contributions from sovereign security researchers and AI engineers. Please review our [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
