# Dynamic Revocation in Asynchronous Multi-Agent Workflows

This repository accompanies the manuscript *Privacy-Preserving Delivery Under Dynamic Revocation in Asynchronous Multi-Agent Workflows*. It contains the frozen benchmarks, archived model plans and experimental records, matching analysis code, and supplemental notes. Benchmark records and receipt-ledger payloads are synthetic. The benchmark files list the public sources used to construct their scenarios.

## Reproduce the archived analyses

Use Python 3.12. The offline verification command requires only the standard library and uses the archived plans and events. It checks the checksums, reproduces the 24-case outcomes under all three fixed-snapshot configurations, recomputes authorized round-trip p95 values, and audits the IPC and TCP fault records against their SQLite ledgers.

```sh
python -B code/verify_artifacts.py --out verification.json
```

The analysis produces a new JSON file. Any rerun that generates fresh model plans requires a separately configured API environment and can produce different plans. The frozen settings and recorded outputs are available below.

## Materials by experiment

| Experiment | Evidence | Code |
| --- | --- | --- |
| Five-arm replay and 60-case development suite | [Frozen cases](evidence/five-arm-replay/frozen-cases.json), [original model inputs and decisions](evidence/five-arm-replay/recorded-model-inputs-and-decisions.json), [execution traces](evidence/five-arm-replay/execution-traces.json), [results](evidence/five-arm-replay/five-arm-results.json) | [Scoring](code/formal60_scoring.py), [replay and reporting](code/formal60_five_report.py) |
| Per-item baseline and component ablation | [Frozen inputs](evidence/component-ablation/frozen-inputs.json), [case receipts and outcomes](evidence/component-ablation/case-receipts-and-outcomes.json), [summary](evidence/component-ablation/summary.json) | [Ablation harness](code/ieee_ablation.py) |
| Frozen holdout and budget comparisons | [Cases and prompts](evidence/holdout/frozen/), [low / 2,048](evidence/holdout/low-2048/), [medium / 2,048](evidence/holdout/medium-2048/), [medium / 8,192](evidence/holdout/medium-8192/), [budget comparison](evidence/holdout/output-budget-comparison.md), [model provenance](evidence/holdout/provenance/model-provenance.md) | [Scoring](code/ieee_holdout_run.py), [snapshot runner](code/ieee_holdout_snapshot.py) |
| Matched global and per-scope lock comparison | [Delivery events](evidence/lock-comparison/deliveries.csv), [revocation events](evidence/lock-comparison/revocations.csv), [historical experiment archive](archives/lock-comparison-and-races.zip) | [Lock implementation](code/ieee_scope_locks.py), [paired analysis](code/ieee_review_paired_rounds.py) |
| Joint encrypted-handle fault experiments | [IPC run and ledger](evidence/ipc-fault/), [loopback TCP run and ledger](evidence/tcp-fault/) | [IPC runner](code/ieee_joint_recovery.py), [TCP runner](code/ieee_joint_recovery_tcp.py), [IPC audit](code/audit_ieee_joint_recovery.py), [TCP audit](code/audit_ieee_joint_recovery_tcp.py) |
| Archive-envelope and low-effort controls | [Archive-envelope results](evidence/revision-controls/archive-envelope-control.json), [case audit](evidence/revision-controls/low-effort-case-audit.json) | [Archive-envelope control](code/ieee_snapshot_seal_control.py) |

[Supplemental notes](evidence/supplemental-notes/experimental_supplement.md) cover the ancillary observations. The [archived supplements](archives/) retain additional development, concurrency, and fault-control records. [SHA256SUMS.txt](SHA256SUMS.txt) lists the distributed files and their digests.

Historical scripts and archives preserve study-time naming and layouts. Use the portable offline verification command above for the primary reproduced outcomes. Repository evidence files retain the archived scientific records, with provider administrative identifiers normalized by the reviewer archive.
