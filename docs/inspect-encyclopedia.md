# Atlas Detection Encyclopedia

This document explains how `atlas inspect` works and how detection profiles map to CloudTrail events.

## Overview

The detection encyclopedia lives in `src/atlas/knowledge/data/api_detection_profiles.yaml`. Each AWS API action Atlas cares about has a profile with:

- **cloudtrail_visibility** — How CloudTrail logs this action (drives score adjustment)
- **base_detection_score** — 0.0–1.0 baseline before logging adjustments
- **guardduty_finding_types** — GuardDuty findings this action can trigger

## CloudTrail Event Types → Atlas Visibility

| CloudTrail Event Type | Atlas Value | Logged by Default? |
|-----------------------|-------------|---------------------|
| **Management** (control plane) | `management_read` or `management_write` | Yes |
| **Data** (data plane) | `data_read` or `data_write` | No |
| **Network activity** (VPC endpoint) | Not modeled | No |
| **Insights** (anomaly) | Not modeled | No |

### Read vs Write

CloudTrail events have a `readOnly` field. Atlas maps:

- `readOnly: true` → `management_read` or `data_read`
- `readOnly: false` → `management_write` or `data_write`

### Management Events

Control plane operations: IAM, STS, EC2 Describe*, S3 bucket-level (ListBuckets, GetBucketPolicy, PutBucketPolicy), Lambda management (ListFunctions, UpdateFunctionCode, CreateFunction), CloudTrail, GuardDuty, etc.

**Logged by default** when a trail exists.

### Data Events

Data plane operations: S3 object-level (GetObject, PutObject, DeleteObject, ListBucket), Lambda Invoke, DynamoDB item-level, SNS Publish, etc.

**Not logged by default.** Must explicitly enable data events for the resource type. Atlas applies a ~0.15 multiplier when data events are off, so these actions score much lower.

## Score Adjustment Formula

```
adjusted_score = base_detection_score × multiplier
```

The multiplier depends on:

1. **CloudTrail visibility** — `management_read`/`management_write` use `cloudtrail_management` (1.0 if active, 0.4 if off). `data_read`/`data_write` use `cloudtrail_data` (1.0 if enabled, 0.15 if off).

2. **GuardDuty** — If the action can trigger GuardDuty findings and GuardDuty is enabled: 1.3×. Otherwise: 0.7×.

3. **SecurityHub / Access Analyzer** — Mutating actions get 1.1× when these are enabled.

## Full vs Minimal Logging (inspect)

`atlas inspect <action>` shows two columns:

| Column | Meaning |
|--------|---------|
| **Full Logging** | CloudTrail active, GuardDuty on, Config, SecurityHub, Access Analyzer |
| **Minimal Logging** | No CloudTrail, no GuardDuty, no Config/SecurityHub/Access Analyzer |

## Profile Coverage

As of the last audit, profiles correctly map:

- **STS, IAM** — All management events ✓
- **S3** — Bucket-level = management; object-level (GetObject, PutObject, DeleteObject, ListBucket) = data ✓
- **EC2** — All management ✓
- **Lambda** — ListFunctions, GetFunction, UpdateFunctionCode, CreateFunction = management; InvokeFunction = data ✓
- **CloudTrail, GuardDuty, Organizations, etc.** — All management 

## Adding New Profiles

1. Add an entry to `api_detection_profiles.yaml` under `profiles:`.
2. Determine `cloudtrail_visibility` from AWS docs:
   - Bucket/resource-level config → `management_read` or `management_write`
   - Object-level, Lambda Invoke, DynamoDB item ops → `data_read` or `data_write`
3. Set `base_detection_score` using the heuristic in the YAML header (0.0–0.1 invisible, 0.1–0.3 low, etc.).
4. Run `atlas inspect <api_action>` to verify.
