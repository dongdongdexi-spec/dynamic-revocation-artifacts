"""Verify the confirmatory receipt boundary against issuance, events and SQLite."""

import argparse
from collections import Counter, defaultdict
import csv
from hashlib import sha256
import json
from pathlib import Path
import sqlite3


WIRE_FIELDS = {'id', 'scope', 'epoch', 'recipient', 'sha256', 'handle'}
BODY_COMMITS = {'committed', 'committed_malformed_ack'}
FENCES = {'fence_persisted', 'precommit_fenced'}


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def csv_rows(path):
    with path.open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream))


def attempt(row):
    return row['id'], int(row['attempt'])


def indexed(rows, identity):
    by_id = {}
    for row in rows:
        k = identity(row)
        assert k not in by_id, (k, 'duplicate evidence')
        by_id[k] = row
    return by_id


def stamp(row):
    return int(row['t_ns'])


def audit(directory):
    protocol = load(directory / 'protocol.json')
    gates = protocol['primary_gates']
    campaign = load(directory / 'campaign.json')
    assert not campaign['smoke'] and campaign['seed'] == protocol['seed']
    assert Counter(r['workers'] for r in campaign['runs']) == dict.fromkeys(
        protocol['worker_counts'], protocol['rounds_per_worker_count'])
    manifest = indexed(load(directory / 'manifest.json'), lambda r: r['id'])
    requests = csv_rows(directory / 'requests.csv')
    issued = {key: manifest[key] for key in {r['id'] for r in requests}}
    controls = indexed(csv_rows(directory / 'controls.csv'), lambda r: r['action'])
    actual_controls = {k: v['status'] for k, v in controls.items() if k in protocol['secondary_controls']}
    assert actual_controls == protocol['secondary_controls']
    receiver = csv_rows(directory / 'receiver_events.csv')
    gateway = csv_rows(directory / 'gateway_events.csv')

    starts = indexed((r for r in requests if r['action'] == 'first_submission'), lambda r: r['id'])
    assert starts.keys() == issued.keys()
    natural = {k for k, v in manifest.items() if v['stage'] not in ('control',)}
    # Some fixed post-campaign controls use an issued handle that was never in a worker schedule.
    assert all(k in starts or k in {c['id'] for c in controls.values()} for k in natural)
    for r in requests:
        m = issued[r['id']]
        assert set(r['wire_item_fields'].split(';')) == WIRE_FIELDS
        assert (r['scope'], int(r['epoch']), r['recipient'], r['sha256'], r['handle_sha256']) == (
            m['scope'], m['epoch'], m['recipient'], m['sha256'], m['handle_sha256'])
    assert all(not {'body', 'nonce', 'sealed', 'key'} & r.keys() for r in manifest.values())

    with sqlite3.connect(directory / 'receipts.sqlite') as db:
        assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',)
        receipts = db.execute('SELECT id,scope,epoch,recipient,sha256,body,attempt FROM receipts').fetchall()
        saved_fences = {(op, n) for op, n in db.execute("SELECT id,attempt FROM attempts WHERE state='fenced'")}
    ledger = indexed(receipts, lambda r: r[0])
    committed = indexed((r for r in receiver if r['event'] in BODY_COMMITS), lambda r: r['id'])
    fences = indexed((r for r in receiver if r['event'] in FENCES), attempt)
    assert ledger.keys() == committed.keys() and fences.keys() == saved_fences
    for key, row in ledger.items():
        m = manifest[key]
        receipt = committed[key]
        assert row[1:5] == (m['scope'], m['epoch'], m['recipient'], m['sha256'])
        assert sha256(row[5].encode()).hexdigest() == m['sha256']
        assert attempt(receipt) == (key, row[6])
        assert receipt['scope'] == row[1] and int(receipt['epoch']) == row[2]

    publications = indexed((r for r in gateway if r['event'] == 'revoke_published'), lambda r: int(r['epoch']))
    revocations = indexed((r for r in gateway if r['event'] == 'revoke_requested'), lambda r: int(r['epoch']))
    assert publications.keys() == revocations.keys() == {r['epoch'] for r in campaign['runs']}
    valid_lease = indexed((r for r in gateway if r['event'] == 'authorized'), attempt)
    decryption = indexed((r for r in gateway if r['event'] == 'decrypt_under_lease'), attempt)
    terminals = indexed((r for r in gateway if r['event'] == 'lease_terminal'), attempt)
    assert valid_lease.keys() == decryption.keys() == terminals.keys()
    old_crypto = [r for r in decryption.values() if r['scope'] == 'withdrawn' and int(r['epoch']) in publications]
    old_receipts = [r for r in committed.values() if r['scope'] == 'withdrawn' and int(r['epoch']) in publications]
    for key, g in valid_lease.items():
        terminal = terminals[key]
        witness = committed.get(key[0]) if terminal['state'] == 'committed' else fences.get(key)
        assert terminal['state'] in ('committed','fenced') and witness is not None
        assert attempt(witness) == key
        assert stamp(decryption[key]) <= stamp(g) <= stamp(witness) <= stamp(terminal)
        if key[1] > 1:
            previous = key[0], key[1]-1
            assert previous in fences and stamp(fences[previous]) <= stamp(terminals[previous]) <= stamp(decryption[key])
        if g['scope'] == 'withdrawn' and int(g['epoch']) in publications:
            assert stamp(terminal) < stamp(publications[int(g['epoch'])])

    settled = indexed((r for r in gateway if r['event'] == 'settled'), lambda r: r['id'])
    nonterminal = sum(k not in settled or settled[k]['state'] not in ('committed','denied') for k in issued)
    unaffected = {k for k, v in issued.items() if v['scope'] == 'independent'}
    actual_ack_suppressed = [r for r in receiver if r['event'] == 'ack_suppressed']
    for r in actual_ack_suppressed:
        assert attempt(committed[r['id']]) == attempt(r) and stamp(committed[r['id']]) <= stamp(r)
    delayed_refusals = [r for r in receiver if r['event'] == 'fenced_original_refused']
    for r in delayed_refusals:
        assert stamp(fences[attempt(r)]) <= stamp(r)
    rebound = {attempt(r) for r in gateway if r['event'] == 'unbound_reply_rejected'}
    bad_ack = [r for r in committed.values() if r['event'] == 'committed_malformed_ack']
    settled_unbound = indexed((r for r in gateway if r['event'] == 'receipt_resolved'), attempt)
    verified_bad_ack = [r for r in bad_ack if attempt(r) in rebound and attempt(r) in settled_unbound
                        and settled_unbound[attempt(r)]['state'] == 'committed']
    assert len(verified_bad_ack) == len(bad_ack)

    overlap = set()
    for key, g in valid_lease.items():
        if g['scope'] == 'withdrawn' and int(g['epoch']) in revocations and (
                stamp(g) <= stamp(revocations[int(g['epoch'])]) < stamp(terminals[key])):
            overlap.add(int(g['epoch']))
    denials = [r for r in gateway if r['event'] == 'denied' and r['scope'] == 'withdrawn'
               and r['id'] in issued and stamp(r) >= stamp(publications[int(r['epoch'])])]
    assert all(r['id'] not in ledger for r in denials)
    assert [k for k in decryption if k[0] == controls['valid_regrant']['id']] == [(controls['valid_regrant']['id'],1)]
    assert all(k[0] not in {controls['retired_after_regrant']['id'], controls['invalid_tag']['id']} for k in decryption)

    values = {'issued_natural_operations': len(issued), 'independent_deliveries': len(unaffected & ledger.keys()),
              'post_publication_old_commits': sum(stamp(r) >= stamp(publications[int(r['epoch'])]) for r in old_receipts),
              'post_publication_old_decrypt_admissions': sum(stamp(r) >= stamp(publications[int(r['epoch'])]) for r in old_crypto),
              'duplicate_durable_receipts': 0, 'digest_mismatches': 0,
              'unbound_worker_requests_in_natural_runs': 0, 'missing_or_nonterminal_natural_operations': nonterminal,
              'authorized_attempts_without_matching_durable_receipt_or_fence_before_lease_release': 0,
              'retired_scope_overlap_rounds_minimum': len(overlap),
              'target_scope_actual_ack_suppression_minimum': sum(r['scope']=='withdrawn' for r in actual_ack_suppressed),
              'target_scope_durable_fence_minimum': sum(r['scope']=='withdrawn' for r in fences.values()),
              'target_scope_attempt_denials_minimum': len(denials),
              'delayed_original_refusals_minimum': len(delayed_refusals),
              'cached_duplicate_outcomes_minimum': sum(r['event']=='duplicate_returned_cached_status' for r in gateway),
              'malformed_ack_rejected_and_resolved_minimum': len(verified_bad_ack)}
    assert gates.keys() == values.keys()
    failures = [name for name, expected in gates.items()
                if (values[name] < expected if name.endswith('_minimum') else values[name] != expected)]
    target_during = [r for r in old_receipts if stamp(revocations[int(r['epoch'])]) < stamp(r)]
    return {'pass': not failures, 'failed_gates': failures, 'gates_measured': values, 'controls': actual_controls,
            'worker_calls': len(requests), 'durable_natural_receipts': len(issued.keys() & ledger.keys()),
            'actual_postcommit_acks_suppressed': len(actual_ack_suppressed), 'durable_fenced_attempts': len(fences),
            'fresh_authorized_retries': sum(attempt_no > 1 for _, attempt_no in valid_lease),
            'authorized_decrypt_attempts': len(decryption), 'old_receipts_before_publication': len(old_receipts),
            'old_receipts_during_write_wait': len(target_during), 'overlap_epochs': sorted(overlap)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    outcome = audit(args.directory)
    args.out.write_text(json.dumps(outcome, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(outcome))
    raise SystemExit(0 if outcome['pass'] else 2)
