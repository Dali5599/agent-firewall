# 🗺️ Roadmap de Nuit : Agent Firewall - Sovereign Security & Observability Proxy for Autonomous AI Agents

> The ultimate local security reverse-proxy and firewall for Claude Code, Cursor, and autonomous AI agents with zero latency overhead.

Enterprise-grade local security proxy intercepting OpenAI and Anthropic API traffic. Features real-time secret redaction, hard token budget circuit breakers, destructive bash command blocking, sovereign SQLite WAL audit logs, a cyberpunk Tailwind web dashboard, and a robust CLI.

## Phases de Développement Prévues

- [ ] **Phase 1** : Project Foundation & Core Configuration - _Initialize project structure, environment configuration, and logging infrastructure._
- [ ] **Phase 2** : Sovereign Audit Database (SQLite WAL) - _Implement robust SQLite WAL storage for request/response logs, token usage, and security blocks._
- [ ] **Phase 3** : Secret Detection & Redaction Engine - _Build high-performance regex and Shannon entropy analyzer to scrub API keys, JWTs, and PII._
- [ ] **Phase 4** : Destructive Command Guard (Bash Guard) - _Analyze tool calls and prompt arguments to intercept dangerous system commands (rm -rf, drop table, etc.)._
- [ ] **Phase 5** : Token Tracker & Budget Circuit Breaker - _Track real-time token consumption and enforce hard limits to prevent runaway API costs._
- [ ] **Phase 6** : Asynchronous Proxy Engine (<2ms Overhead) - _Implement FastAPI and httpx transparent reverse-proxy supporting streaming SSE and standard API payloads._
- [ ] **Phase 7** : Cyberpunk Web Dashboard & Real-Time WebSocket - _Develop Tailwind CSS single-page application with live WebSocket feed of intercepted requests and stats._
- [ ] **Phase 8** : Complete CLI Suite - _Create feature-rich CLI using Typer for managing the firewall (start, stats, logs, test)._
- [ ] **Phase 9** : Deployment, Containerization & Demo Assets - _Prepare Docker setup, documentation, and automated GitHub publishing assets._
- [ ] **Phase 10** : Exhaustive Unit Testing Suite - _Write 20+ comprehensive pytest unit tests ensuring 100% pass rate across all modules._
