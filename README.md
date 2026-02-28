# Atlas

**AWS Cloud Adversary Emulation Platform**

---

> **⚠️ This tool is still under development.** APIs and behavior may change. Use with caution in production environments.

---

## Attack Knowledge: pathfinding.cloud Integration

Atlas incorporates **all techniques from [pathfinding.cloud](https://github.com/DataDog/pathfinding.cloud)** (parginfd.cloud — Datadog's verified AWS IAM privilege escalation paths). The 65+ attack paths—covering IAM, EC2, Lambda, ECS, Glue, CodeBuild, SageMaker, SSM, CloudFormation, Bedrock, AppRunner, and more—are synced automatically on first run and merged into the attack graph. This gives Atlas comprehensive, battle-tested coverage of real-world AWS privilege escalation techniques.

---

## Contributing Red Team Techniques

**We welcome contributions of new red team techniques.** If you have attack paths, privilege escalation methods, or AWS abuse techniques you'd like to add to Atlas, please open an issue or submit a pull request. The planner and attack graph are designed to be extended—see `src/atlas/planner/attack_graph.py` and `src/atlas/knowledge/data/api_detection_profiles.yaml` for how techniques are modeled.

---

## What is Atlas?

Atlas is a next-generation AWS cloud adversary emulation platform. It helps red teams and security researchers:

- **Discover** attack paths from a given identity (recon + attack graph)
- **Plan** multi-step privilege escalation chains
- **Simulate** execution without making AWS API calls (BloodHound-style — mapping only, no execution)
- **Explain** attack paths with AI-powered or template-based explanations

---

## Features

| Feature | Description |
|---------|-------------|
| **pathfinding.cloud integration** | All 65+ verified IAM privilege escalation paths from pathfinding.cloud (Datadog) — auto-synced on first run |
| **BloodHound-style queries** | `who-can-reach-admin`, `blast-radius`, `external-trusts`, `wildcards`, `privileged-principals`, `detection-map` |
| **Detection encyclopedia** | CloudTrail + GuardDuty profiles for each API action; `atlas inspect` shows detection scores |
| **AI-powered explanations** | LLM-grounded explanations using verified pathfinding.cloud paths |
| **Streamlit GUI** | Interactive web UI for exploring cases and attack paths |
| **Access key decoder** | `atlas inspect-key` decodes AWS account ID from access key ID (offline) |
| **Case management** | Save, list, and delete cases with `atlas cases` and `atlas delete-case` |
| **Tiered permission recon** | Identity, policy, trust, guardrail, resource, and bruteforce tiers |
| **Noise budget** | Stealth-aware planning with configurable detection cost limits |

---

## Requirements

- Python 3.12+
- AWS credentials configured (e.g. `~/.aws/credentials`)

---

## Installation

**Install from PyPI (recommended):**

```bash
pip install atlas-redteam
```

**Or with pipx (isolated environment, no venv needed):**

```bash
pipx install atlas-redteam
```

**Update to latest version:**

```bash
pip install --upgrade atlas-redteam
# or
pipx upgrade atlas-redteam
```

> **Note for maintainers:** To publish new versions so users get updates, see [docs/RELEASE.md](docs/RELEASE.md).

**For development (editable install):**

```bash
git clone https://github.com/Haggag-22/Atlas.git
cd Atlas
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Configure AWS profile
atlas config --profile my-profile --region us-east-1

# Run recon + planning (creates a case)
atlas plan --case mycase

# List attack paths and simulate
atlas simulate --case mycase --attack-path AP-01

# Explain an attack path
atlas explain --case mycase --attack-path AP-01

# Open the GUI
atlas gui --case mycase
```

---

## Commands

| Command | Description |
|--------|-------------|
| `atlas config` | Set or show AWS profile and region |
| `atlas plan` | Run reconnaissance + planning. Uses pathfinding.cloud (65+ verified IAM privesc paths) automatically—syncs on first run if needed. |
| `atlas simulate` | Simulate an attack path (no AWS calls) |
| `atlas cases` | List saved cases |
| `atlas delete-case` | Delete a saved case |
| `atlas explain` | Explain an attack path (AI or template) |
| `atlas gui` | Open the Streamlit web UI |
| `atlas query` | BloodHound-style queries: who-can-reach-admin, blast-radius, external-trusts, wildcards, privileged-principals, detection-map |
| `atlas inspect` | Inspect detection profiles for API actions (CloudTrail + GuardDuty) |
| `atlas inspect-key` | Decode AWS account ID from access key ID (offline) |

---

## Output Structure

```
output/<case>/
├── case.json           # Case metadata
├── plan/               # Recon + planning
│   ├── env_model.json
│   ├── attack_edges.json
│   ├── graph.json
│   ├── attack_paths.json
│   └── ...
├── sim/                # Simulation results (if run)
└── explanations.json   # Cached AI/template explanations
```

---

## Attack Techniques

Atlas models techniques from **pathfinding.cloud** and its own attack pattern registry, including:

- **IAM**: Role assumption, access key creation, policy attachment, inline policy injection, PassRole abuse, trust policy modification, permissions boundary manipulation
- **EC2**: PassRole via instance profile, userdata read/modify, EC2 Instance Connect
- **Lambda**: PassRole, code/config injection, credential theft
- **ECS, Glue, CodeBuild, SageMaker**: PassRole and service-specific escalation
- **SSM**: Session Manager, tag-based enablement
- **CloudFormation, Bedrock, AppRunner**: PassRole and resource abuse
- **S3**: Bucket policy, object read/write

Detection costs and noise levels are derived from CloudTrail and GuardDuty profiles in `src/atlas/knowledge/`.

---

## Discovered Resources

The recon engine collects the following resource types (configurable via `recon.resource_types`):

| Resource | Service | Key Security Data |
|----------|---------|-------------------|
| S3 Buckets | S3 | Bucket policies, Public Access Block |
| EC2 Instances | EC2 | Instance profiles, IMDS config, security groups |
| Lambda Functions | Lambda | Execution roles, resource policies, environment variables |
| RDS Instances | RDS | Public accessibility, encryption, IAM auth, snapshots |
| KMS Keys | KMS | Key policies, grants, rotation status |
| Secrets Manager Secrets | Secrets Manager | Resource policies, rotation, KMS encryption |
| SSM Parameters | SSM | Parameter types (SecureString), KMS key IDs |
| CloudFormation Stacks | CloudFormation | Stack roles, capabilities, outputs |

---

## License

MIT
