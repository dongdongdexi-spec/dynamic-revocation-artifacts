# Supplemental Experimental Evidence

This supplement preserves the original control schedules, readouts, and denominators. Use the main article for the paired lock comparison and the joint encrypted-handle results.

## S1. Historical Barrier-Controlled Delivery and Regression

The local process experiment recorded 2,856 submissions and verified all 1,666 durable receipt bodies against their expected digests. The gateway refused all 1,190 restricted submissions made after revocation publication, and none appeared in the recipient database. The independent authorized item was correctly received in all 1,428 submissions. Of the 238 protected items received, 119 were positive controls that retained authorization and the other 119 committed before revocation but were deliberately acknowledged afterward. The recipient commit and sender acknowledgment are separate events in the recorded trace.

*Table S-I. Delivery counts by schedule in the historical barrier-controlled experiment. The unmodified rerun reproduced these counts.*

| Schedule | Protected bodies received | Protected submissions refused | Independently authorized bodies received |
|---|---:|---:|---:|
| Retained authorization | 119 | 0 | 119 |
| Queued before revocation | 0 | 357 | 357 |
| Result released after revocation | 0 | 357 | 357 |
| Partial revocation | 0 | 357 | 357 |
| Committed before revocation, acknowledgment delayed | 119 | 0 | 119 |
| Restored by a replacement worker after revocation | 0 | 119 | 119 |
| **Total** | **238** | **1,190** | **1,428** |

## S2. Natural Races and Lost Acknowledgments

The fault campaign uses six and 16 independent workers for four rounds at each size. Each worker generates 18 synthetic operation identifiers. A common start aligns the workers, and an independent timer schedules revocation at a seeded delay of 25–190 ms into the round. The campaign uses seed 472019. Submissions and revocation proceed independently after the common start. The seed fixes the injection schedule, while thread, process, and TCP scheduling determine the realized interleaving. The intended load alternates the scope that will be revoked and an independent scope.

The injection conditions are normal delivery, a confirmed pre-commit failure, loss of the recipient-to-gateway acknowledgment after commit, concurrent duplicate requests, delayed handling of the original request, and acknowledgment loss with temporary lookup unavailability. A request rejected at the gateway does not reach the recipient to trigger its assigned fault. The campaign sends synthetic bodies directly and uses the scope lease and idempotent receipt protocol. The matched performance experiment separately exercises the encrypted body and key-slot path. The lost acknowledgment is a recipient-to-gateway event. It differs from the historical and matched controls in which the gateway delays an acknowledgment to the worker after receiving the recipient's durable result.

The receiver records a monotonic timestamp immediately after SQLite commit and before publishing the event to lookup or acknowledging it. The independent audit joins these events with request identifiers, body digests, durable attempt fences, and the gateway's lease and publication events. It checks for duplicate durable bodies, old-epoch commits after publication, completion of unaffected work, and evidence of a previous attempt's retirement before retry. The recovery measurement starts when the outcome becomes uncertain and ends when a receipt or fence becomes known. A 30 ms checkpoint separately measures unresolved recipient facts and operations without an overall terminal outcome.

The eight natural-race rounds generated 1,584 distinct operations and 2,314 client calls. The recipient ledger contained 893 unique, digest-verified bodies. All 792 unaffected-scope operations committed, and 691 target-scope operations were denied. The remaining 101 target-scope bodies committed before publication. Eighty-eight committed before the revocation request and 13 while the writer was waiting. In all eight rounds, revocation was requested while an authorized target-scope submission was active and at least one target outcome was uncertain. The audit found zero target commits at or after publication and zero duplicate bodies.

*Table S-II. Fault campaign by preassigned injection mode. A request denied at the gateway does not trigger its recipient-side injection.*

| Assigned mode | Logical operations | Durable receipts | Terminal denials | First call pending |
|---|---:|---:|---:|---:|
| Normal | 260 | 144 | 116 | 0 |
| Confirmed pre-commit failure | 262 | 155 | 107 | 0 |
| Acknowledgment suppressed after commit | 266 | 156 | 110 | 156 |
| Concurrent duplicate request | 268 | 152 | 116 | 1 |
| Delayed original request | 266 | 141 | 125 | 160 |
| Acknowledgment loss and temporary lookup unavailability | 262 | 145 | 117 | 145 |
| **Total** | **1,584** | **893** | **691** | **462** |

The receiver suppressed 301 post-commit acknowledgments and persisted 314 attempt fences. Fresh authorization allowed 293 resubmissions after those fences and denied the other 21 after revocation. The receiver rejected 157 delayed original handlers that encountered their fence. The audit joined all 1,207 authorized attempts to a terminal lease record and its durable receipt or fence. It also verified that each retry followed a durable fence for the preceding attempt. No duplicate body was committed across the 268 concurrent duplicate requests.

Of the 462 operations that entered an uncertain state, 211 still lacked a definitive recipient fact 30 ms later and 287 had yet to reach an overall terminal state. All operations settled by the end of the campaign. Time to resolve the recipient fact was 24.992 / 243.789 ms p50 / p95, with a maximum of 8,671.095 ms. Revocation request-to-publication latency had a median of 143.694 ms and a range of 110.339–239.872 ms across eight rounds. The interpolated p95 was 222.395 ms. Reconciliation is measured per affected operation and publication per round.

## S3. Downstream Observation of Revocation

In the status-only experiment, all 22,463 old-authority requests decided after publication were refused among 56,920 total requests. Three status acknowledgments for requests accepted before publication reached the worker at or after publication. Table S-III reports the timing around the switch. Last acceptance is expressed as a positive lead before publication. First denial and the worker receipt are measured forward from publication. The last column first takes the slowest worker's first denial receipt in each round and then summarizes those round values. At 64 workers this p95 was 6.508 ms. The interval includes polling, scheduling, and TCP response time. It describes how quickly a worker observed a decision from one central gateway.

*Table S-III. Status-only switch timing. Entries show p50 / p95 in milliseconds.*

| Workers | Lead of last gateway acceptance | Time to first gateway denial | Slowest worker receipt of first denial |
|---:|---:|---:|---:|
| 1 | 1.724 / 3.903 | 1.718 / 2.248 | 1.840 / 2.352 |
| 6 | 2.601 / 5.120 | 1.163 / 4.427 | 3.605 / 5.325 |
| 16 | 2.529 / 5.672 | 1.608 / 5.321 | 5.388 / 6.006 |
| 32 | 2.089 / 5.502 | 1.788 / 4.941 | 5.508 / 6.183 |
| 64 | 2.510 / 5.774 | 1.704 / 4.929 | 6.024 / 6.508 |

Archived figure and measurements for Status-only revocation measurements for independent workers and the central gateway

## S4. Local Slot Operations up to 2,048 Holders

At 2,048 holders, the separate in-process series measured a shared-slot update of 0.900 / 4.805 µs p50 / p95 and one index entry removed. Generic graph traversal took 199.100 / 260.135 µs and visited 2,049 nodes. A simulated acknowledged update to each holder took 61.200 / 68.810 µs and produced 2,048 local acknowledgments. Each method and size used 120 local samples. These are operation-level comparisons on a synthetic structure with no network or recipient transactions. The generic traversal does not implement VERA's federated proof protocol. [VERA](https://arxiv.org/abs/2608.30091)

Archived figure and measurements for In-process revocation work as the number of holders increases

## S5. Exploratory Twenty-Case Topology Comparison

An earlier exploratory topology comparison used 20 cases from the development suite and paired a single Luna session with a Luna coordinator and six separate Luna role sessions. Both used the same privacy prompt and a delivery path without a current authorization check. Twelve cases exposed the revised authorization before planning and the remaining eight restored an older pending item after revocation. This comparison informs the analysis of topology and scheduling errors. Its cases are excluded from the independent holdout counts.

The 20-case exploratory comparison exposed the same eight restored pending items in each topology. All disclosures occurred at the intermediate stage. The single-agent workflow completed 20/20 cases and the coordinator-plus-six-workers workflow completed 10/20. In the ten incomplete multi-agent cases, the selected administrative slot preceded the allowed start. The work allocation and the messages delivered to the coordinator both differed across topologies.


[Frozen-case and historical receipt archive](../../archives/frozen-holdout-and-controls.zip) · [Matched and initial fault campaign archive](../../archives/lock-comparison-and-races.zip) · [Polling and scale archive](../../archives/status-probing-and-scaling.zip) · [Topology diagnostic archive](../../archives/topology-and-scaling.zip)
