"""Verify the archived artifact checksums and rerun the core offline analyses."""

import argparse
from collections import defaultdict
import csv
from hashlib import sha256
import json
from pathlib import Path
from statistics import quantiles

from audit_ieee_joint_recovery import audit
from audit_ieee_joint_recovery_tcp import audit_tcp
from ieee_holdout_run import execute


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'evidence'


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def verify_checksums():
    count = 0
    for line in (ROOT / 'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines():
        expected, name = line.split('  ', 1)
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'Checksum mismatch: {name}')
        count += 1
    return count


def rescore_holdout():
    holdout = EVIDENCE / 'holdout'
    cases = load(holdout / 'frozen/cases-24.json')['cases']
    settings = {}
    for config in ('low-2048', 'medium-2048', 'medium-8192'):
        directory = holdout / config
        recorded = load(directory / 'case_results.json')
        result = defaultdict(list)
        for case in cases:
            inputs = load(directory / 'calls' / case['id'] / 'case.json')
            for topology in ('single', 'multi'):
                for gate in ('off', 'on'):
                    row, _ = execute(case, inputs[topology]['plan'], gate == 'on', gate)
                    result[f'{topology}_{gate}'].append(row)
        if dict(result) != recorded:
            raise ValueError(f'Holdout outcomes differ: {config}')
        settings[config] = {key: {metric: sum(r[metric] for r in rows)
                                  for metric in ('any_leak', 'task_success', 'safe_success')}
                            for key, rows in result.items()}
    return settings


def lock_p95():
    samples = defaultdict(list)
    with (EVIDENCE / 'lock-comparison/deliveries.csv').open(encoding='utf-8', newline='') as stream:
        for row in csv.DictReader(stream):
            if row['scenario'] == 'retained' and row['scope'] != 'control':
                if row['allowed'] != '1':
                    raise ValueError('Retained delivery was denied')
                group = row['workload'], int(row['workers']), row['mode']
                samples[group].append(int(row['e2e_ns']) / 1e6)
    if len(samples) != 20 or any(len(points) != group[1] * 8 for group, points in samples.items()):
        raise ValueError('Matched-lock sample balance changed')
    return [{'workload': workload, 'workers': workers, 'lock': mode, 'samples': len(points),
             'p95_ms': quantiles(points, n=100, method='inclusive')[94]}
            for (workload, workers, mode), points in sorted(samples.items())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, help='Optional output JSON; defaults to stdout.')
    args = parser.parse_args()
    checksums = verify_checksums()
    tcp = EVIDENCE / 'tcp-fault'
    outcome = {
        'files_verified': checksums,
        'holdout': rescore_holdout(),
        'matched_lock_p95': lock_p95(),
        'ipc_fault': audit(EVIDENCE / 'ipc-fault'),
        'tcp_fault': audit_tcp(tcp, tcp / 'protocol.ipc.original.json'),
    }
    serialized = json.dumps(outcome, indent=2, ensure_ascii=False) + '\n'
    if args.out is None:
        print(serialized, end='')
    else:
        args.out.write_text(serialized, encoding='utf-8')


if __name__ == '__main__':
    main()
