# HexMind v0.1.0-alpha

AI-powered local penetration testing assistant.

## Quick Start

```bash
make install
make pull-model
hexmind scan example.com
```

## Commands

- `hexmind scan <target>` — Run a full scan
- `hexmind history` — List past scans
- `hexmind report <id> --format pdf` — Export report
- `hexmind targets` — List known targets
- `hexmind doctor` — Check dependencies

## Scan Profiles

- `quick` — nmap + whois only, 1 AI pass
- `standard` — all tools except gobuster, 2 AI passes (default)
- `deep` — all tools, 3+ AI passes
- `stealth` — low-noise, slow timing

## Requirements

- Python 3.11+
- Ollama (`curl https://ollama.ai/install.sh | sh`)
- System tools: nmap, whois, whatweb, nikto, dig, curl, gobuster, sslscan

## Roadmap

| Version | Stage  | Description                                       |
|---------|--------|---------------------------------------------------|
| 0.1.0   | Alpha  | Core scaffold, DB layer ← current                 |
| 0.2.0   | Beta   | All recon runners, AI engine, agentic loop        |
| 0.3.0   | RC     | Reports, web search, CVE lookup, full integration |
| 1.0.0   | Stable | Production-ready first release                    |
| 2.0.0   | Stable | Nuclei, batch scanning, plugin system             |
| 3.0.0   | Stable | REST API, team features, scheduled scans          |
