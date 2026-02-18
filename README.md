# Atlas

**AWS Cloud Adversary Emulation Platform**

---

> **⚠️ This tool is still under development.** APIs and behavior may change. Use with caution in production environments.

---

## Contributing Red Team Techniques

**We welcome contributions of new red team techniques.** If you have attack paths, privilege escalation methods, or AWS abuse techniques you'd like to add to Atlas, please open an issue or submit a pull request. The planner and attack graph are designed to be extended—see `src/atlas/planner/attack_graph.py` and `src/atlas/knowledge/data/api_detection_profiles.yaml` for how techniques are modeled.

---

## What is Atlas?

Atlas is a next-generation AWS cloud adversary emulation platform. It helps red teams and security researchers:

- **Discover** attack paths from a given identity (recon + attack graph)
- **Plan** multi-step privilege escalation chains
- **Simulate** execution without making AWS API calls
- **Execute** attack paths with configurable stealth and safety guardrails
- **Explain** attack paths with AI-powered or template-based explanations

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
| `atlas plan` | Run reconnaissance + planning, save to `output/<case>/plan/` |
| `atlas simulate` | Simulate an attack path (no AWS calls) |
| `atlas run` | Execute an attack path (uses AWS) |
| `atlas cases` | List saved cases |
| `atlas delete-case` | Delete a saved case |
| `atlas explain` | Explain an attack path (AI or template) |
| `atlas gui` | Open the Streamlit web UI |
| `atlas inspect` | Inspect detection profiles for API actions |

---

## Output Structure

```
output/<case>/
├── case.json           # Case metadata
├── plan/               # Recon + planning
│   ├── env_model.json
│   ├── attack_edges.json
│   ├── attack_paths.json
│   └── ...
├── sim/                # Simulation results (if run)
├── run/                # Execution results (if run)
└── explanations.json   # Cached AI/template explanations
```

---

## Attack Techniques (Examples)

Atlas models techniques such as:

- Role assumption (`sts:AssumeRole`)
- Access key creation (`iam:CreateAccessKey`)
- Policy attachment (`iam:AttachUserPolicy`, `iam:AttachRolePolicy`)
- Inline policy injection (`iam:PutUserPolicy`, `iam:PutRolePolicy`)
- PassRole abuse (Lambda, etc.)
- Trust policy modification (`iam:UpdateAssumeRolePolicy`)
- Lambda code injection
- S3 read/write access

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
