"""Run the frozen joint recovery campaign over two IPv4 loopback TCP hops."""

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import platform
import random
import socket
import sqlite3
import struct
import threading
import time
from dataclasses import replace
from pathlib import Path

import ieee_joint_recovery as joint

HOST = '127.0.0.1'
TRANSPORT = 'ipv4_loopback_tcp'
MAX_FRAME_BYTES = 65536
HEADER = struct.Struct('!I')


class TCPFrames:
    """A small connection adapter for the archived request-correlation code."""

    def __init__(self, stream):
        self.stream = stream

    def read_exact(self, length):
        buffer = bytearray()
        while len(buffer) < length:
            more = self.stream.recv(length - len(buffer))
            if not more:
                raise EOFError('TCP endpoint closed')
            buffer.extend(more)
        return bytes(buffer)

    def send(self, value):
        payload = json.dumps(value, separators=(',', ':')).encode('utf-8')
        if not 0 < len(payload) <= MAX_FRAME_BYTES:
            raise OSError('TCP frame outside configured bounds')
        self.stream.sendall(HEADER.pack(len(payload)) + payload)

    def recv(self):
        length, = HEADER.unpack(self.read_exact(HEADER.size))
        if not 0 < length <= MAX_FRAME_BYTES:
            raise OSError('TCP frame outside configured bounds')
        try:
            return json.loads(self.read_exact(length))
        except (UnicodeError, ValueError) as exc:
            raise OSError('Invalid TCP frame') from exc

    def close(self):
        try:
            self.stream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.stream.close()


def listener():
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        stream.bind((HOST, 0))
        stream.listen(1)
        stream.settimeout(18)
        return stream
    except BaseException:
        stream.close()
        raise


def tcp_client(address):
    if address[0] != HOST:
        raise ValueError('Only an IPv4 loopback benchmark is supported')
    stream = socket.create_connection(address, timeout=3)
    stream.settimeout(None)
    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return TCPFrames(stream)


def tcp_server(stream, handler, parallelism, errors, peers):
    try:
        with stream:
            accepted, peer = stream.accept()
        if peer[0] != HOST:
            accepted.close()
            raise ValueError('Non-loopback peer')
        peers.append({'local': list(accepted.getsockname()), 'peer': list(peer)})
        accepted.settimeout(None)
        accepted.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        joint.serve(TCPFrames(accepted), handler, parallelism, errors)
    except (OSError, ValueError) as exc:
        errors.append(repr(exc))


def loopback_probe():
    with listener() as endpoint:
        address = endpoint.getsockname()
        with socket.create_connection(address, timeout=2) as client:
            remote, peer = endpoint.accept()
            with remote:
                assert peer[0] == HOST
                expected = {'transport': TRANSPORT, 'message': 'local probe'}
                TCPFrames(client).send(expected)
                assert TCPFrames(remote).recv() == expected
    return address


def receiver_main(database, journal, tcp_peer_log, ready):
    receiver = joint.BoundReceiver(database)
    errors, peers = [], []
    try:
        stream = listener()
        ready.send(stream.getsockname())
        ready.close()
        tcp_server(stream, lambda packet, _: receiver.apply(packet), 64, errors, peers)
        journal.write_text(json.dumps(receiver.events), encoding='utf-8')
        tcp_peer_log.write_text(json.dumps(peers), encoding='utf-8')
        assert not errors, errors
    finally:
        receiver.db.close()


class WorkerReport:
    def __init__(self, pipe, application_connection):
        self.pipe = pipe
        self.local = application_connection.stream.getsockname()
        self.peer = application_connection.stream.getpeername()

    def send(self, message):
        kind, payload = message
        if kind == 'done':
            payload = [row | {'tcp_client_port': self.local[1], 'tcp_gateway_port': self.peer[1]} for row in payload]
        self.pipe.send((kind, payload))

    def close(self):
        self.pipe.close()


def worker_main(address, schedule, seed, starting, report):
    connection = tcp_client(address)
    joint.worker_main(connection, schedule, seed, starting, WorkerReport(report, connection))


def gateway_endpoint(gateway, peers):
    stream = listener()
    address = stream.getsockname()

    def handle(packet, notify):
        if packet['action'] == 'status':
            return gateway.lookup(packet['item'])
        return gateway.submit(packet['item'], notify)

    thread = threading.Thread(target=tcp_server, args=(stream, handle, 4, gateway.errors, peers), daemon=True)
    thread.start()
    return address, thread


def run_round(ctx, gateway, worker_count, epoch, seed, item_count, delay, cutoff):
    for scope in joint.SCOPES:
        gateway.grant(scope, epoch)
    starting = ctx.Event()
    active, observations, peers = [], [], []
    try:
        for worker in range(worker_count):
            schedule = []
            for index in range(item_count):
                fault = joint.FAULTS[(index // 2 + worker + epoch) % len(joint.FAULTS)]
                item = gateway.issue(f'{epoch:04}-{worker:02}-{index:02}', joint.SCOPES[index % 2], epoch,
                                     fault, 'natural', worker)
                schedule.append((item, fault == 'duplicate'))
            left, right = ctx.Pipe()
            address, service_thread = gateway_endpoint(gateway, peers)
            child = ctx.Process(target=worker_main, args=(address, schedule,
                                seed + worker * 11939, starting, right))
            child.start()
            right.close()
            active.append((child, left, service_thread, address))
        for child, pipe, _, _ in active:
            assert pipe.poll(20) and pipe.recv() == ('ready', child.pid)
        if epoch == 1:
            gateway.old_control = gateway.issue('retired-control', 'withdrawn', epoch, 'normal', 'control')

        def revoke_later():
            starting.wait()
            time.sleep(delay)
            gateway.revoke(epoch)

        writer = threading.Thread(target=revoke_later, daemon=True)
        writer.start()
        started = joint.NOW()
        starting.set()
        deadline = time.monotonic() + cutoff
        for child, pipe, _, _ in active:
            assert pipe.poll(max(0, deadline - time.monotonic())), child.pid
            tag, detail = pipe.recv()
            assert tag == 'done'
            observations.extend(detail)
            child.join(timeout=5)
            assert child.exitcode == 0
        writer.join(max(0, deadline - time.monotonic()))
        assert not writer.is_alive(), 'Revocation did not publish within the cutoff'
        assert len(peers) == worker_count
        return observations, {'stage': 'natural', 'epoch': epoch, 'workers': worker_count,
                'planned_delay_ns': int(delay * 1e9), 'started_ns': started,
                'worker_pids': [child.pid for child, _, _, _ in active],
                'worker_endpoints': [{'pid': child.pid, 'local': list(address)} for child, _, _, address in active],
                'accepted_worker_tcp_peers': sorted(peers, key=lambda peer: peer['local'][1])}
    finally:
        for child, pipe, service_thread, _ in active:
            pipe.close()
            if child.is_alive():
                child.terminate()
                child.join()
            service_thread.join(timeout=5)


def controls(gateway, final_epoch):
    gateway.grant('withdrawn', final_epoch)
    fresh = gateway.issue('regrant-control', 'withdrawn', final_epoch, 'normal', 'control')
    corrupted = gateway.issue('invalid-tag-control', 'withdrawn', final_epoch, 'normal', 'control')
    envelope = gateway.issued[corrupted['id']]
    gateway.issued[corrupted['id']] = replace(envelope, sealed=bytes([envelope.sealed[0] ^ 1]) + envelope.sealed[1:])
    peers = []
    address, thread = gateway_endpoint(gateway, peers)
    client = joint.PipeClient(tcp_client(address))
    try:
        return [joint.send(client, item, label) for label, item in (
            ('retired_after_regrant', gateway.old_control), ('valid_regrant', fresh),
            ('binding_mismatch', fresh | {'recipient': 'incorrect-synthetic-recipient'}),
            ('cross_handle', fresh | {'handle': corrupted['handle']}),
            ('invalid_tag', corrupted), ('regrant_status', fresh),
        )], peers
    finally:
        assert client.call({'action': 'stop'}) == {'state': 'stopping'}
        client.close()
        thread.join(timeout=5)


def frozen_protocol(path):
    original = path.read_bytes()
    protocol = json.loads(original)
    assert tuple(protocol['fault_rotation']) == joint.FAULTS
    assert tuple(protocol['scope_sequence'].split(', ')[:2]) == joint.SCOPES
    assert (protocol['seed'], tuple(protocol['worker_counts']), protocol['rounds_per_worker_count'],
            protocol['jobs_per_worker']) == (joint.SEED, joint.WORKERS, joint.ROUNDS, joint.ITEMS)
    protocol.pop('transport_amendment_before_formal_run', None)
    return protocol | {'transport': TRANSPORT, 'original_ipc_protocol_sha256': hashlib.sha256(original).hexdigest(),
                       'bootstrap_control': 'Spawn and readiness use local pipes. Both application hops use TCP.'}


def run(out, source_protocol, smoke):
    probe_address = loopback_probe()
    protocol = frozen_protocol(source_protocol)
    out.mkdir(parents=True, exist_ok=True)
    database = out / 'receipts.sqlite'
    if database.exists():
        raise ValueError('--out must not already contain a receipts database')
    (out / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n', encoding='utf-8')
    journal = out / 'receiver_events.json'
    peer_log = out / 'recipient_tcp_peers.json'
    ctx = mp.get_context('spawn')
    parent, child = ctx.Pipe(duplex=False)
    receiver = ctx.Process(target=receiver_main, args=(database, journal, peer_log, child))
    receiver.start()
    child.close()
    try:
        assert parent.poll(15)
        receiver_address = parent.recv()
        receipt_connection = tcp_client(receiver_address)
        gateway_to_recipient_tcp = {'local': list(receipt_connection.stream.getsockname()),
                                    'peer': list(receipt_connection.stream.getpeername())}
        receipt_client = joint.PipeClient(receipt_connection)
        gateway = joint.Gateway(receipt_client)
        gateway.errors = []
        rng = random.Random(protocol['seed'])
        rows, schedules = [], []
        low, high = protocol['withdrawal_timer_ms_range']
        for workers in ((2,) if smoke else protocol['worker_counts']):
            for trial in range(1 if smoke else protocol['rounds_per_worker_count']):
                epoch = len(schedules) + 1
                result, schedule = run_round(ctx, gateway, workers, epoch, protocol['seed'] + epoch * 6211,
                                             protocol['jobs_per_worker'], rng.uniform(low / 1000, high / 1000),
                                             protocol['round_cutoff_seconds_after_common_start'])
                rows.extend(result)
                schedules.append(schedule)
                print(f'{workers} workers, round {trial + 1}: {len(result)} TCP calls', flush=True)
        control_rows, control_peers = controls(gateway, len(schedules) + 1)
        assert not gateway.errors, gateway.errors
        time.sleep(joint.LATE_ORIGINAL + .020)
        assert receipt_client.call({'action': 'stop'}) == {'state': 'stopping'}
        receipt_client.close()
        receiver.join(timeout=10)
        assert receiver.exitcode == 0
        joint.store_csv(out / 'requests.csv', rows)
        joint.store_csv(out / 'controls.csv', control_rows)
        joint.store_csv(out / 'gateway_events.csv', gateway.events)
        joint.store_csv(out / 'receiver_events.csv', json.loads(journal.read_text(encoding='utf-8')))
        (out / 'manifest.json').write_text(json.dumps(gateway.manifest, indent=2), encoding='utf-8')
        (out / 'campaign.json').write_text(json.dumps({
            'seed': protocol['seed'], 'items': protocol['jobs_per_worker'], 'scenarios': joint.FAULTS,
            'scopes': joint.SCOPES, 'smoke': smoke, 'transport': TRANSPORT, 'probe_address': probe_address,
            'environment': {'platform': platform.platform(), 'python': platform.python_version(),
                            'sqlite': sqlite3.sqlite_version, 'logical_cpu_count': os.cpu_count()},
            'receiver_pid': receiver.pid, 'gateway_pid': mp.current_process().pid,
            'gateway_to_recipient_tcp': gateway_to_recipient_tcp,
            'recipient_tcp_peers': json.loads(peer_log.read_text(encoding='utf-8')),
            'control_tcp_peers': control_peers, 'runs': schedules,
        }, indent=2), encoding='utf-8')
    finally:
        parent.close()
        if receiver.is_alive():
            receiver.terminate()
            receiver.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--protocol', type=Path, required=True)
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args()
    run(args.out, args.protocol, args.smoke)


if __name__ == '__main__':
    main()
