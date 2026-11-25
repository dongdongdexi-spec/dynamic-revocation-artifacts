"""Freeze, execute, and audit the paired dispatch and component trials."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from secrets import token_bytes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from epoch_workflow_eval import Binding, Envelope, Gateway, Submission, encode
from formal60_scoring import check_case_receipts, digest, read, read_locked_manifest, require, unique_rows, write


MAX_ATTEMPTS = 2
ARMS = {
    'independent_retained': {'mode': 'independent', 'invalidate': False, 'continue': False},
    'independent_invalidated': {'mode': 'independent', 'invalidate': True, 'continue': False},
    'batch_E0_C0': {'mode': 'batch', 'invalidate': False, 'continue': False},
    'batch_E0_C1': {'mode': 'batch', 'invalidate': False, 'continue': True},
    'batch_E1_C0': {'mode': 'batch', 'invalidate': True, 'continue': False},
    'batch_E1_C1': {'mode': 'batch', 'invalidate': True, 'continue': True},
}
PRIMARY = ('independent_retained', 'independent_invalidated', 'batch_E1_C1')
FACTORIAL = tuple(arm for arm in ARMS if arm.startswith('batch_'))


def freeze(source, output):
    manifest, cases, source_lock = read_locked_manifest(source / '锁定题库.json', source / '锁定规则.json')
    trajectory = read(source / '实验执行轨迹.json')
    model = read(source / '模型输入与原始决策.json')
    require(trajectory['manifest_sha256'] == digest(manifest), 'Execution trace manifest differs')
    rows = unique_rows(trajectory['arms']['full']['rows'])
    planned = unique_rows(model['opaque_out'])
    planners = unique_rows(model['opaque_input'])
    final_out = unique_rows(model['full_final_out'])
    require(rows.keys() == cases.keys() == planned.keys() == planners.keys() == final_out.keys(), 'Case set differs')
    deck = []
    for cid, case in cases.items():
        row = rows[cid]
        require(row['model_plan'] == planned[cid] and row['final_decision'] == final_out[cid], 'Plan differs')
        deck.append({
            **{k: case[k] for k in ('id', 'family', 'timing_cell', 'clock', 'policy_v1', 'policy_v2', 'deliverables')},
            'unit': case['story']['unit'], 'plan': planned[cid], 'final': final_out[cid],
            'handle': planners[cid]['data_from_F']['A']['handle'],
        })
    require(not output.exists(), 'The frozen deck already exists')
    protocol = {
        'name': 'paired-fixed-plan-dispatch-and-2x2-component-replay',
        'source_case_hash': source_lock['case_sha256'], 'source_trace_hash': digest(trajectory),
        'source_model_hash': digest(model), 'deck_hash': digest(deck),
        'primary_arms': list(PRIMARY), 'primary_population': [r['id'] for r in deck],
        'factorial_arms': list(FACTORIAL), 'factorial_population': [r['id'] for r in deck if r['family'] == 'P'],
        'arms': ARMS, 'max_transport_attempts_per_item': MAX_ATTEMPTS,
        'retries': 'Only a receiver transient failure explicitly before commit warrants retry. Recheck permission on each attempt.',
        'retry_check': 'Separate 15-P trace. First receiver attempt for each shared/admin item fails before commit.',
        'positive_control': 'Every S10 protected ENQUEUE in a fresh gateway under V1, one tick before revocation.',
        'scope': 'Single-runner logical times, real AES-GCM and local in-memory JSON receiver. No latency claims.',
        'success': 'shared and admin exact receipt values and intended destinations, using the frozen scorer',
        'privacy': 'exact protected synthetic value in either stage receiver-visible fields or body, case counted once',
        'same_tick_rule': 'Revocation takes effect first at its tick. V1 commit may stay in the ledger if earlier.',
        'admin_plan_policy': 'Same previously observed full-arm final decision is replayed in every arm, with no S12 rerun.',
    }
    write(output, {'protocol': protocol, 'deck': deck})


class Receiver:
    """Record what the sink actually accepts, after serialization and transient failures."""

    def __init__(self, inject_failure):
        self.inject_failure = inject_failure
        self.attempts = Counter()
        self.commits = {}

    def submit(self, payload, tick):
        channel = payload['channel']
        self.attempts[channel] += 1
        attempt = self.attempts[channel]
        require(attempt <= MAX_ATTEMPTS, 'Transport retry cap exceeded')
        if self.inject_failure and channel in ('shared', 'admin') and attempt == 1:
            return 'TRANSIENT_BEFORE_COMMIT'
        require(channel not in self.commits, 'Receiver accepted a duplicate item')
        self.commits[channel] = {'tick': tick, 'receipt': json.loads(encode(payload))}
        return 'COMMITTED'


def new_gate(case):
    scope = case['policy_v1']['protected']
    bound = Binding(case['id'], scope['id'], scope['recipient'], scope['grant'], '精确核账', case['unit'])
    gate = Gateway(True)
    cipher = AESGCM(AESGCM.generate_key(256))
    nonce = token_bytes(12)
    token = case['handle']
    ciphertext = cipher.encrypt(nonce, encode(case['deliverables']['protected']['value']), encode((token, asdict(bound))))
    gate.envelopes[token] = Envelope(bound, nonce, ciphertext)
    gate.active[bound.grant] = (bound, cipher)
    return gate, bound


def replay(case, arm, inject_failure=False, positive=False):
    cid, clock = case['id'], case['clock']
    gate, bound = new_gate(case)
    sink = Receiver(inject_failure)
    events = []
    queued = {name: case['plan'][name] for name in ('protected', 'shared') if case['plan'][name]['action'] == 'ENQUEUE'}
    scopes = case['policy_v1'] if positive else case['policy_v2']
    slot_available = None
    if not positive:
        if arm['invalidate']:
            gate.expire(bound.grant)
        slot_available = gate.active.get(bound.grant) is not None
        events.append({'tick': clock['revoke'], 'event': 'revoked', 'old_slot_lookup': slot_available})

    def check(name):
        scope = scopes[name]
        expected_scope = case['policy_v1'][name]
        return scope['right'] == 'ALLOW' and all(scope.get(k) == expected_scope.get(k) for k in ('id', 'grant', 'recipient'))

    def dispatch(name, request, tick):
        for _ in range(MAX_ATTEMPTS):
            if not check(name):
                events.append({'tick': tick, 'item': name, 'event': 'DENIED_CURRENT_POLICY'})
                return
            value = request['slot' if name == 'admin' else 'value']
            if name == 'protected':
                require(tick < clock['revoke'], 'Protected commit reached current policy after revocation')
                status = gate.submit_exact(Submission(cid + '-protected', bound, value))
                require(status == 'DELIVERED', f'{cid} V1 handle could not be opened: {status}')
                value = gate.receipts[-1]['quantity']
            payload = {'channel': name, 'value': value, 'recipient': scopes[name]['recipient'], 'body': request['body']}
            status = sink.submit(payload, tick)
            events.append({'tick': tick, 'item': name, 'event': status, 'attempt': sink.attempts[name]})
            if status == 'COMMITTED':
                return
        require(False, f'{cid} {name} uses more than one retry')

    if positive:
        dispatch('protected', queued['protected'], clock['revoke'] - 1)
        return {'id': cid, 'decryptions': gate.decryptions, 'commits': sink.commits, 'events': events}

    has_batch = arm['mode'] == 'batch' and case['family'] == 'P' and len(queued) == 2
    rejected = has_batch and any(not check(name) for name in queued)
    first = clock['visible']
    kept = []
    if rejected:
        events.append({'tick': first, 'event': 'BATCH_REJECTED', 'items': list(queued)})
        if arm['continue']:
            kept = [name for name in queued if check(name)]
            events.append({'tick': first, 'event': 'CONTINUATION_SCHEDULED', 'items': kept})
            for name in kept:
                dispatch(name, queued[name], first)
    else:
        for name, request in queued.items():
            dispatch(name, request, first)
    final = case['final']
    if final['action'] == 'SEND':
        dispatch('admin', final, clock['final'])
    mid = [x['receipt'] for key, x in sink.commits.items() if key != 'admin']
    last = [x['receipt'] for key, x in sink.commits.items() if key == 'admin']
    mid_ok, mid_leak = check_case_receipts(case, 'S11', mid)
    final_ok, final_leak = check_case_receipts(case, 'S12', last)
    complete = (mid_ok | final_ok) == {'shared', 'admin'}
    return {'id': cid, 'case_plan_hash': digest([case['plan'], final]), 'clock': clock, 'family': case['family'],
            'old_slot_lookup': slot_available, 'old_ciphertext_retained': case['handle'] in gate.envelopes,
            'protected_attempted': 'protected' in queued, 'protected_committed': 'protected' in sink.commits,
            'batch_rejected': bool(rejected), 'continued': bool(kept), 'transport_attempts': dict(sink.attempts),
            'decryptions': gate.decryptions, 'commits': sink.commits, 'events': events,
            'mid_correct': sorted(mid_ok), 'final_correct': sorted(final_ok), 'mid_leak': mid_leak,
            'final_leak': final_leak, 'any_leak': mid_leak or final_leak, 'task_success': complete,
            'safe_task_success': complete and not (mid_leak or final_leak)}


def summarize(rows):
    names = ('protected_attempted', 'protected_committed', 'old_slot_lookup', 'old_ciphertext_retained',
             'mid_leak', 'final_leak', 'any_leak', 'task_success', 'safe_task_success',
             'batch_rejected', 'continued', 'decryptions')
    return {'n': len(rows), **{name: sum(row[name] for row in rows) for name in names},
            'correct_shared': sum('shared' in row['mid_correct'] for row in rows),
            'correct_admin': sum('admin' in row['final_correct'] for row in rows),
            'transport_attempts': sum(sum(row['transport_attempts'].values()) for row in rows),
            'transport_retries': sum(sum(n - 1 for n in row['transport_attempts'].values()) for row in rows)}


def report(output, results):
    labels = {'independent_retained': '强基线：独立逐项、留旧槽', 'independent_invalidated': '独立逐项、失效旧槽',
              'batch_E0_C0': '批次，关闭失效、关闭续办', 'batch_E0_C1': '批次，关闭失效、开启续办',
              'batch_E1_C0': '批次，开启失效、关闭续办', 'batch_E1_C1': '完整方案：批次、失效旧槽、续办'}
    by = results['summaries']
    lines = ['# 强基线与组件消融', '',
             '所有组重放同一份已记录的句柄入队计划及完整方案的行政计划。两项获准交付按原规则评分。'
             '每个交付项最多尝试两次，只有收件端在提交前明确返回暂时故障时才允许重试，而且每次都重新核权。'
             '逐项强基线使用相同句柄和送达前核权，默认保留旧槽、关闭续办。第二个逐项组只把旧槽失效打开，用于区分调度方式和槽状态。', '',
             '## 60 题配对主实验', '',
             '| 方法 | 全流程泄露 | 任务成功 | 撤权后旧槽查得到 | 获准共享项正确 | 行政项正确 |',
             '|---|---:|---:|---:|---:|---:|']
    for arm, s in by['main'].items():
        lines.append(f'| {labels[arm]} | {s["any_leak"]}/{s["n"]} | {s["task_success"]}/{s["n"]} | '
                     f'{s["old_slot_lookup"]}/{s["n"]} | {s["correct_shared"]}/{s["n"]} | {s["correct_admin"]}/{s["n"]} |')
    main = by['main']
    paired = results['paired_main_success']
    lines += ['', f'逐项强基线与完整方案的任务成功判定同为成功 {paired.get("1:1", 0)} 题、'
                  f'同为失败 {paired.get("0:0", 0)} 题，基线独自成功 {paired.get("1:0", 0)} 题，完整方案独自成功 {paired.get("0:1", 0)} 题。'
                  f'仍能从原旧槽查到密钥的题数分别为 {main["independent_retained"]["old_slot_lookup"]} 和 {main["batch_E1_C1"]["old_slot_lookup"]}。', '',
              '## 15 题部分撤权的 2×2 消融', '',
              '| 批次设置 | 全流程泄露 | 任务成功 | 旧槽查得到 | 整批拒绝 | 续办触发 |',
              '|---|---:|---:|---:|---:|---:|']
    for arm, s in by['factorial'].items():
        lines.append(f'| {labels[arm]} | {s["any_leak"]}/{s["n"]} | {s["task_success"]}/{s["n"]} | '
                     f'{s["old_slot_lookup"]}/{s["n"]} | {s["batch_rejected"]} | {s["continued"]} |')
    lines += ['', '旧槽查找使用当前密钥索引实际 `get` 的结果。所有组保留原密文，受限提交在 ACL 层拒绝。'
                  '因此槽失效测到的是网关不能再从该槽取得密钥。内存擦除、提前复制的秘密和外部密钥缓存超出实验范围。'
                  '续办的收益出现在整批必须拒绝的条件下，其独立作用通过同一槽状态下的开关结果估计。', '',
              '## 单独的重试验证', '',
              '| 方法 | 任务成功 | 传输重试 | 全流程泄露 |', '|---|---:|---:|---:|']
    for arm, s in by['retry_control'].items():
        lines.append(f'| {labels[arm]} | {s["task_success"]}/{s["n"]} | {s["transport_retries"]} | {s["any_leak"]}/{s["n"]} |')
    pos = results['positive_correct']
    lines += ['', f'重试验证使用 15 道部分撤权题，让每项获准共享或行政提交的第一次尝试在写入收件台前失败。'
                  f'原权限保留对照中，{pos}/{len(results["positive_control"])} 个旧句柄在撤权之前正确核权、AES-GCM 解密并提交对应受限值。', '',
              '本实验使用本地内存收件台和冻结逻辑时钟，收件载荷经过 JSON 编解码并留有提交记录。'
              '行政计划使用原完整方案的固定决定，因而结果衡量执行层交付差异。并发传输时延由独立实验测量。', '',
              '复跑方式为 `python ieee_ablation.py run --frozen 冻结输入.json --out 复跑结果`，需安装 `cryptography`。'
              '`逐题收件与结果.json` 含完整收件及重试事件，`逐题对照.csv` 可用于直接分析。', '']
    (output / '强基线与组件消融.md').write_text('\n'.join(lines), encoding='utf-8')


def execute(frozen, output):
    source = read(frozen)
    protocol, deck = source['protocol'], source['deck']
    require(protocol['deck_hash'] == digest(deck), 'Frozen plan hash mismatch')
    require(protocol['arms'] == ARMS and protocol['max_transport_attempts_per_item'] == MAX_ATTEMPTS, 'Protocol changed')
    require(len(deck) == 60 and len(unique_rows(deck)) == 60, 'Need 60 distinct cases')
    subset = [r for r in deck if r['family'] == 'P']
    require(len(subset) == 15 and [r['id'] for r in subset] == protocol['factorial_population'], 'Partial scope subset mismatch')
    require([r['id'] for r in deck] == protocol['primary_population'], 'Primary population mismatch')
    results = {'main': {arm: [replay(row, ARMS[arm]) for row in deck] for arm in PRIMARY},
               'factorial': {arm: [replay(row, ARMS[arm]) for row in subset] for arm in FACTORIAL},
               'retry_control': {arm: [replay(row, ARMS[arm], inject_failure=True) for row in subset]
                                 for arm in ('independent_retained', 'batch_E1_C1')}}
    positive_cases = [row for row in deck if row['plan']['protected']['action'] == 'ENQUEUE']
    positive = [replay(row, ARMS['batch_E1_C1'], positive=True) for row in positive_cases]
    n_positive = sum(r['decryptions'] == 1 and r['commits']['protected']['tick'] < row['clock']['revoke'] and
                     r['commits']['protected']['receipt']['value'] == row['deliverables']['protected']['value'] and
                     r['commits']['protected']['receipt']['recipient'] == row['deliverables']['protected']['recipient']
                     for r, row in zip(positive, positive_cases, strict=True))
    require(n_positive == len(positive) > 0, 'Retained positive control failed')
    for modes in results.values():
        for arm, rows in modes.items():
            require(all(r['old_ciphertext_retained'] and r['old_slot_lookup'] == (not ARMS[arm]['invalidate']) and
                        r['decryptions'] == 0 and not r['protected_committed'] for r in rows), 'ACL or slot invariant failed')
    for rows in results['retry_control'].values():
        require(all(r['transport_attempts'].get('shared') == r['transport_attempts'].get('admin') == MAX_ATTEMPTS
                    for r in rows), 'Equal retry allowance was not exercised')
    baseline, full = (results['main'][arm] for arm in ('independent_retained', 'batch_E1_C1'))
    paired = Counter(f'{int(a["task_success"])}:{int(b["task_success"])}' for a, b in zip(baseline, full, strict=True))
    summaries = {phase: {a: summarize(rows) for a, rows in methods.items()} for phase, methods in results.items()}
    results.update({'positive_control': positive, 'positive_correct': n_positive, 'summaries': summaries,
                    'paired_main_success': dict(paired), 'deck_hash': protocol['deck_hash']})
    write(output / '逐题收件与结果.json', results)
    write(output / '汇总.json', {'summaries': summaries, 'positive_correct': n_positive,
                               'positive_n': len(positive), 'paired_main_success': dict(paired)})
    columns = ('id', 'family', 'old_slot_lookup', 'old_ciphertext_retained', 'protected_attempted',
               'protected_committed', 'batch_rejected', 'continued', 'decryptions', 'mid_leak', 'final_leak',
               'any_leak', 'task_success', 'safe_task_success')
    with (output / '逐题对照.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=('phase', 'arm', *columns, 'transport_attempts'))
        writer.writeheader()
        for phase in ('main', 'factorial', 'retry_control'):
            for arm, rows in results[phase].items():
                for r in rows:
                    writer.writerow({'phase': phase, 'arm': arm, **{key: r[key] for key in columns},
                                     'transport_attempts': sum(r['transport_attempts'].values())})
    report(output, results)
    print(f'Validated {sum(len(rows) for phase in (results[p] for p in summaries) for rows in phase.values())} replays and {n_positive} V1 receiver controls')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('freeze')
    prepare.add_argument('--source', type=Path, required=True)
    prepare.add_argument('--frozen', type=Path, required=True)
    run = commands.add_parser('run')
    run.add_argument('--frozen', type=Path, required=True)
    run.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'freeze':
        freeze(args.source, args.frozen)
    else:
        execute(args.frozen, args.out)
