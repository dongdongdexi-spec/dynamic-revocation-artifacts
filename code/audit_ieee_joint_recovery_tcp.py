"""Join TCP peer evidence and the frozen inputs with the existing independent SQLite audit."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import random

from audit_ieee_joint_recovery import audit, csv_rows, load

HOST = '127.0.0.1'
TRANSPORT = 'ipv4_loopback_tcp'


def address(raw):
    assert len(raw) == 2 and raw[0] == HOST and 0 < raw[1] < 65536
    return tuple(raw)


def audit_tcp(root, original):
    result = audit(root)
    protocol = load(root / 'protocol.json')
    original_bytes = original.read_bytes()
    expected = json.loads(original_bytes)
    assert protocol['original_ipc_protocol_sha256'] == sha256(original_bytes).hexdigest()
    different = {key for key in protocol.keys() & expected.keys() if protocol[key] != expected[key]}
    assert different == {'transport'}
    assert protocol.keys() - expected.keys() == {'original_ipc_protocol_sha256', 'bootstrap_control'}
    assert expected.keys() - protocol.keys() == {'transport_amendment_before_formal_run'}
    campaign = load(root / 'campaign.json')
    assert protocol['transport'] == campaign['transport'] == TRANSPORT
    assert campaign['scenarios'] == expected['fault_rotation']
    assert campaign['items'] == expected['jobs_per_worker'] and len(campaign['runs']) == 10
    assert campaign['receiver_pid'] != campaign['gateway_pid']
    address(campaign['probe_address'])

    peers = campaign['recipient_tcp_peers']
    assert len(peers) == 1 and len(campaign['control_tcp_peers']) == 1
    gateway_peer = campaign['gateway_to_recipient_tcp']
    assert address(gateway_peer['local']) == address(peers[0]['peer'])
    assert address(gateway_peer['peer']) == address(peers[0]['local'])
    control = campaign['control_tcp_peers'][0]
    address(control['peer'])
    address(control['local'])

    rng = random.Random(expected['seed'])
    low, high = expected['withdrawal_timer_ms_range']
    client_ports, expected_jobs = {}, {}
    manifest = {entry['id']: entry for entry in load(root / 'manifest.json') if entry['stage'] == 'natural'}
    for ordinal, run in enumerate(campaign['runs'], start=1):
        worker_count, pids = run['workers'], run['worker_pids']
        assert run['epoch'] == ordinal
        assert run['planned_delay_ns'] == int(rng.uniform(low / 1000, high / 1000) * 1e9)
        assert len(set(pids)) == worker_count and not {campaign['receiver_pid'], campaign['gateway_pid']} & set(pids)
        peer_by_local = {address(t['local']): address(t['peer']) for t in run['accepted_worker_tcp_peers']}
        assert len(peer_by_local) == len(run['accepted_worker_tcp_peers']) == worker_count
        assert [entry['pid'] for entry in run['worker_endpoints']] == pids
        for index, endpoint in enumerate(run['worker_endpoints']):
            gateway_addr = address(endpoint['local'])
            client_ports[ordinal, endpoint['pid']] = (peer_by_local[gateway_addr][1], gateway_addr[1])
            for job in range(expected['jobs_per_worker']):
                i = (job // 2 + index + ordinal) % len(campaign['scenarios'])
                jobid = f'{ordinal:04}-{index:02}-{job:02}'
                expected_jobs[jobid] = campaign['scopes'][job % 2], campaign['scenarios'][i], index
    assert {jobid: (m['scope'], m['fault'], m['worker']) for jobid, m in manifest.items()} == expected_jobs
    requests = csv_rows(root / 'requests.csv')
    for row in requests:
        assert (int(row['tcp_client_port']), int(row['tcp_gateway_port'])) == client_ports[int(row['epoch']), int(row['worker_pid'])]
    assert Counter(row['id'] for row in requests if row['action'] == 'first_submission') == Counter(expected_jobs.keys())
    return result | {'application_transport': TRANSPORT, 'scheduled_tcp_worker_connections': len(client_ports),
                     'scheduled_tcp_recipient_connections': len(peers), 'environment': campaign['environment'],
                     'ipc_protocol_sha256': protocol['original_ipc_protocol_sha256']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--ipc-protocol', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = audit_tcp(args.directory, args.ipc_protocol)
    rendered = json.dumps(result, indent=2) + '\n'
    args.out.write_text(rendered, encoding='utf-8')
    print(rendered)
    raise SystemExit(0 if result['pass'] else 2)


if __name__ == '__main__':
    main()
