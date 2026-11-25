"""Re-analyze archived lock results with paired-round, not request-level, resampling."""

import argparse
from collections import defaultdict
import csv
from hashlib import sha256
import gzip
import json
from pathlib import Path

import numpy as np


K = 20_000
SEED = 20261125
SCALES = (1, 6, 16, 32, 64)
WORKLOADS = ('hot', 'multi')
MODES = ('global', 'rwlock')


def load(path):
    opener = gzip.open if path.suffix == '.gz' else open
    blocks = defaultdict(lambda: defaultdict(dict))
    with opener(path, 'rt', encoding='utf-8', newline='') as stream:
        for row in csv.DictReader(stream):
            if row['scenario'] != 'retained' or row['scope'] == 'control':
                continue
            assert row['allowed'] == '1'
            cell = row['workload'], int(row['workers'])
            modes = blocks[cell][int(row['round'])]
            order, points = modes.setdefault(row['mode'], (int(row['arm_order']), {}))
            assert order == int(row['arm_order']) and row['worker'] not in points
            points[row['worker']] = int(row['e2e_ns']) / 1e6
    return blocks


def p95(x, axis=None):
    return np.quantile(x, .95, axis=axis, method='linear')


def interval(x):
    return [float(a) for a in np.quantile(x, (.025, .975), method='linear')]


def estimate(blocks, n, rng):
    assert len(blocks) == 8
    ordered = [blocks[round_id] for round_id in sorted(blocks)]
    for block in ordered:
        assert set(block) == set(MODES)
        assert {block[m][0] for m in MODES} == {0, 1}
        assert all(set(block[mode][1]) == {str(i) for i in range(n)} for mode in MODES)
    matrices = [np.array([[block[mode][1][str(i)] for i in range(n)] for block in ordered]) for mode in MODES]
    global_ms, scope_ms = matrices
    sizes = (K, len(ordered))
    idx = rng.integers(0, len(ordered), size=sizes)
    rep_global = p95(global_ms[idx].reshape(K, -1), axis=1)
    rep_scope = p95(scope_ms[idx].reshape(K, -1), axis=1)
    arm_order = np.array([block['global'][0] for block in ordered])
    order_summary = {}
    for order, label in ((0, 'global_first'), (1, 'rwlock_first')):
        selection = arm_order == order
        if np.any(selection):
            x, y = p95(global_ms[selection]), p95(scope_ms[selection])
            order_summary[label] = {'n_pairs': int(sum(selection)), 'reduction_pct': float(100 * (1-y/x))}
    g, s = p95(global_ms), p95(scope_ms)
    return {'n_round_pairs': len(ordered), 'n_pooled_requests_per_arm': global_ms.size,
            'global_p95_ms': float(g), 'rwlock_p95_ms': float(s),
            'global_minus_rwlock_ms': float(g-s), 'reduction_pct': float(100 * (1-s/g)),
            'paired_round_bootstrap_95pct_difference_ms': interval(rep_global-rep_scope),
            'paired_round_bootstrap_95pct_reduction_pct': interval(100*(1-rep_scope/rep_global)),
            'round_pairs_with_lower_rwlock_p95': int(sum(p95(scope_ms, axis=1) < p95(global_ms, axis=1))),
            'order_sensitivity': order_summary}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--deliveries', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    cells = load(a.deliveries)
    assert set(cells) == {(workload, n) for workload in WORKLOADS for n in SCALES}
    rng = np.random.default_rng(SEED)
    results = {f'{workload}:{n}': estimate(cells[workload,n], n, rng) for workload in WORKLOADS for n in SCALES}
    opener = gzip.open if a.deliveries.suffix == '.gz' else open
    with opener(a.deliveries, 'rb') as stream:
        raw_sha256 = sha256(stream.read()).hexdigest()
    result = {'seed': SEED, 'resamples': K, 'underlying_csv_sha256': raw_sha256,
              'unit': 'paired retained-authority rounds; pool selected ordinary requests within each resample',
              'scope': 'descriptive retrospective analysis, conditional on the archived runs and workload',
              'cells': results}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    for key in ('hot:64','multi:64'):
        print(key, json.dumps(results[key]))


if __name__ == '__main__':
    main()
