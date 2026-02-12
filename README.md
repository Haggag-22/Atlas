# Atlas – AWS Cloud Adversary Emulation Framework

**This framework is still in development.** Functionality and APIs may change.

Atlas is a Python framework for **AWS cloud adversary emulation** in lab environments. It runs ordered, campaign-based scenarios aligned to MITRE ATT&CK, with a modular design, safety controls, telemetry, and a plugin system so you can model realistic cloud tradecraft in a controlled way.

> **Lab use only.** Intended for use only in AWS accounts you own or are explicitly authorized to test. You are responsible for compliance with AWS Terms of Service and your organization’s policies.

---

## What it does

- **Campaign orchestration** – Executes techniques in sequence as defined in YAML campaigns. State is carried between steps (discovered accounts, roles, resources, credentials references, findings). Runs produce a structured JSON timeline and a human-readable report.

- **Technique plugins** – Each technique is a plugin with a standard interface (identifier, description, required permissions, inputs, `execute`, outputs, optional `rollback`). Campaigns reference technique IDs and pass parameters, so new behaviors can be added without changing the core.

- **Reconnaissance** – Scans local directories or Git repositories (no internet scraping) for leaked secrets and common misconfig patterns. Findings are normalized and can be used as inputs to campaigns.

- **Telemetry** – Records each action in a consistent schema: timestamp, actor, AWS API, resource ARN, region, result, error, and evidence pointers. Supports optional enrichment from CloudTrail when logs are available.

- **Safety controls** – Hard allowlist of AWS account IDs and regions, mandatory confirmation for destructive actions, dry-run mode, and rate limiting with jitter to reduce burst traffic. A clear banner states that the tool is for lab use only.

---

## Built-in techniques (read-only / safe)

| Technique                  | Description                                      | MITRE   |
|---------------------------|--------------------------------------------------|---------|
| Identity discovery        | Caller identity and IAM user listing             | T1078   |
| Permission enumeration    | User and role attached/inline policies           | T1069   |
| Role trust analysis       | IAM role trust policies                          | T1098   |
| S3 enumeration            | S3 buckets and public access block settings     | T1530   |
| Security group enumeration| EC2 security groups and rules                    | T1565   |
| IAM policy simulation     | SimulatePrincipalPolicy for selected actions     | T1069   |

---

## Project structure

The codebase is organized under `src/atlas/`: `cli` (entrypoint and config), `core` (config, state, plugin contract, orchestrator, safety), `plugins` (registry and technique implementations), `recon` (local scanner), `telemetry` (event schema and recorder), and `utils` (e.g. rate limiting). Example campaigns and config live in `campaigns/` and `config/`; sample outputs are in `examples/output/`. See **CONTRIBUTING.md** for development and adding techniques.

---

## License

MIT. Use only in authorized lab environments.
