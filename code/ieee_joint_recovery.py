"""Local confirmatory scope-revocation campaign with opaque envelopes and a durable receiver."""

import argparse
import hashlib
import json
import multiprocessing as mp
from queue import Empty, Queue
import random
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ieee_race_receipts import (
    LATE_ORIGINAL, MAX_ATTEMPTS, NOW, PENDING_SAMPLE, RECIPIENT, SCOPES,
    SEND_TIMEOUT, Receiver, digest, event, key, store_csv,
)
from ieee_scope_locks import ScopeRWLocks


SEED = 734087
WORKERS = (6, 16)
ROUNDS = 5
ITEMS = 18
FAULTS = ('normal', 'precommit_failure', 'lost_ack', 'duplicate', 'late_original', 'query_outage', 'malformed_ack')
BINDING_FIELDS = ('id', 'scope', 'epoch', 'recipient', 'sha256')
WORKER_FIELDS = (*BINDING_FIELDS, 'handle')
REPLY_FIELDS = ('state', 'attempt', 'binding')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class PipeClient:
    """Match replies to individual calls, including replies arriving after a timeout."""

    def __init__(self, connection):
        self.connection = connection
        self.send_guard = threading.Lock()
        self.pending_guard = threading.Lock()
        self.pending = {}
        self.serial = 0
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            while True:
                serial, reply = self.connection.recv()
                with self.pending_guard:
                    waiter = self.pending.get(serial)
                    if waiter is not None:
                        waiter.put_nowait(reply)
        except (OSError, EOFError):
            with self.pending_guard:
                for waiter in self.pending.values():
                    if waiter.empty():
                        waiter.put_nowait(None)

    def call(self, packet, timeout=15):
        waiter = Queue(maxsize=1)
        with self.pending_guard:
            self.serial += 1
            serial = self.serial
            self.pending[serial] = waiter
        try:
            with self.send_guard:
                self.connection.send((serial, packet))
            return waiter.get(timeout=timeout)
        except (Empty, OSError, EOFError):
            return None
        finally:
            with self.pending_guard:
                self.pending.pop(serial)

    def close(self):
        self.connection.close()


def serve(connection, handler, parallelism, errors):
    """Serve a dedicated inherited endpoint and dispatch independently scheduled handlers."""
    send_guard = threading.Lock()

    def reply(serial, result):
        try:
            with send_guard:
                connection.send((serial, result))
        except (OSError, EOFError):
            pass

    def invoke(serial, packet):
        def notify(value):
            nonlocal sent
            if not sent:
                sent = True
                reply(serial, value)

        sent = False
        try:
            notify(handler(packet, notify))
        except Exception as exc:
            errors.append(repr(exc))
            notify(None)

    try:
        with ThreadPoolExecutor(max_workers=parallelism) as pool:
            while True:
                try:
                    serial, packet = connection.recv()
                except (OSError, EOFError):
                    break
                if packet['action'] == 'stop':
                    reply(serial, {'state': 'stopping'})
                    break
                pool.submit(invoke, serial, packet)
    finally:
        connection.close()


class BoundReceiver(Receiver):
    def transaction(self, action, item, attempt):
        result, kind = super().transaction(action, item, attempt)
        if result['state'] in ('committed', 'fenced'):
            result = {'state': result['state'], 'attempt': result.get('attempt', attempt),
                      'binding': dict(zip(BINDING_FIELDS, key(item), strict=True))}
        if kind == 'committed' and item['fault'] == 'malformed_ack':
            # The recorded transaction commits normally. Only the subsequent reply is changed.
            result['binding']['sha256'] = 'corrupt-ack-digest'
            kind = 'committed_malformed_ack'
        return result, kind


def receiver_main(database, journal, connection, ready):
    receiver = BoundReceiver(database)
    try:
        ready.send('ready')
        ready.close()
        errors = []
        serve(connection, lambda packet, _: receiver.apply(packet), 64, errors)
        journal.write_text(json.dumps(receiver.events), encoding='utf-8')
        assert not errors, errors
    finally:
        receiver.db.close()


@dataclass(frozen=True)
class Issued:
    binding: tuple
    handle: str
    fault: str
    nonce: bytes
    sealed: bytes

    def worker_descriptor(self):
        return dict(zip(WORKER_FIELDS, (*self.binding, self.handle), strict=True))


class Gateway:
    def __init__(self, receiver):
        self.receiver = receiver
        self.locks = ScopeRWLocks(SCOPES)
        self.events = []
        self.keys = {}
        self.issued = {}
        self.jobs = {}
        self.manifest = []

    def grant(self, scope, epoch):
        with self.locks.write(scope):
            assert (scope, epoch) not in self.keys
            self.keys[scope, epoch] = AESGCM.generate_key(bit_length=256)
            event(self.events, 'grant', {'scope': scope, 'epoch': epoch})

    def issue(self, op, scope, epoch, fault, stage, worker=None):
        # Workers see neither payload nor AEAD key. Payload entropy is independent of scheduling.
        body = f'SYNTHETIC:{op}:{secrets.token_hex(48)}'
        binding = (op, scope, epoch, RECIPIENT, digest(body))
        handle = secrets.token_urlsafe(24)
        nonce = secrets.token_bytes(12)
        sealed = AESGCM(self.keys[scope, epoch]).encrypt(nonce, body.encode(), canonical((*binding, handle)))
        record = Issued(binding, handle, fault, nonce, sealed)
        self.issued[op] = record
        self.jobs[op] = {'lock': threading.Lock(), 'state': None}
        self.manifest.append(dict(zip(BINDING_FIELDS, binding, strict=True)) | {
            'stage': stage, 'worker': worker, 'fault': fault,
            'handle_sha256': hashlib.sha256(handle.encode()).hexdigest(),
            'sealed_sha256': hashlib.sha256(sealed).hexdigest(),
        })
        return record.worker_descriptor()

    def revoke(self, epoch):
        item = {'scope': 'withdrawn', 'epoch': epoch}
        event(self.events, 'revoke_requested', item)
        with self.locks.write('withdrawn'):
            assert self.keys.pop(('withdrawn', epoch))
            event(self.events, 'revoke_published', item)

    def verified_descriptor(self, item):
        if set(item) != set(WORKER_FIELDS):
            return None
        record = self.issued.get(item['id'])
        if record is None or item != record.worker_descriptor():
            return None
        return record

    @staticmethod
    def verified_reply(reply, item, attempt):
        if not isinstance(reply, dict) or set(reply) != set(REPLY_FIELDS):
            return None
        if reply['binding'] != {field: item[field] for field in BINDING_FIELDS}:
            return None
        matching_attempt = type(reply['attempt']) is int and reply['attempt'] == attempt
        if matching_attempt and reply['state'] in ('committed', 'fenced'):
            return reply
        return None

    def resolve(self, item, attempt, answer, notify):
        valid = self.verified_reply(answer, item, attempt)
        if valid is not None:
            return valid
        event(self.events, 'uncertain', item, attempt=attempt)
        notify({'state': 'pending'})
        metadata = {field: item[field] for field in BINDING_FIELDS} | {'fault': item['fault']}
        if answer is not None:
            event(self.events, 'unbound_reply_rejected', item, attempt=attempt, source='submission')
        while True:
            # An absent lookup does not close the lease. Fence atomically against the receiver's commit.
            answer = self.receiver.call({'action': 'lookup', 'item': metadata, 'attempt': attempt})
            if isinstance(answer, dict) and answer.get('state') == 'absent':
                event(self.events, 'lookup_absent_still_pending', item, attempt=attempt)
                answer = self.receiver.call({'action': 'fence', 'item': metadata, 'attempt': attempt})
            valid = self.verified_reply(answer, item, attempt)
            if valid is not None:
                event(self.events, 'receipt_resolved', item, attempt=attempt, state=valid['state'])
                return valid
            event(self.events, 'unbound_or_unavailable_still_pending', item, attempt=attempt)
            time.sleep(.012)

    def submit(self, descriptor, notify):
        record = self.verified_descriptor(descriptor)
        if record is None:
            return {'state': 'binding_mismatch'}
        state = self.jobs[descriptor['id']]
        item = dict(zip(BINDING_FIELDS, record.binding, strict=True)) | {'fault': record.fault}
        with state['lock']:
            if state['state'] is not None:
                event(self.events, 'duplicate_returned_cached_status', item, state=state['state']['state'])
                return state['state']
            for attempt in range(1, MAX_ATTEMPTS + 1):
                with self.locks.read(item['scope']):
                    encryption_key = self.keys.get((item['scope'], item['epoch']))
                    if encryption_key is None:
                        event(self.events, 'denied', item, attempt=attempt)
                        outcome = {'state': 'denied'}
                        break
                    try:
                        body = AESGCM(encryption_key).decrypt(
                            record.nonce, record.sealed, canonical((*record.binding, record.handle)),
                        ).decode()
                    except InvalidTag:
                        event(self.events, 'open_rejected', item, attempt=attempt)
                        outcome = {'state': 'invalid_ciphertext'}
                        break
                    assert digest(body) == item['sha256']
                    event(self.events, 'decrypt_under_lease', item, attempt=attempt)
                    event(self.events, 'authorized', item, attempt=attempt)
                    answer = self.receiver.call({'action': 'submit', 'item': item | {'body': body},
                                                 'attempt': attempt}, timeout=SEND_TIMEOUT)
                    outcome = self.resolve(item, attempt, answer, notify)
                    # Only exactly bound durable outcomes can release this lease.
                    event(self.events, 'lease_terminal', item, attempt=attempt, state=outcome['state'])
                    if outcome['state'] != 'fenced':
                        break
                time.sleep(.001)
            state['state'] = {'state': outcome['state']}
            event(self.events, 'settled', item, state=outcome['state'])
            return state['state']

    def lookup(self, descriptor):
        record = self.verified_descriptor(descriptor)
        if record is None:
            return {'state': 'binding_mismatch'}
        state = self.jobs[descriptor['id']]
        with state['lock']:
            return state['state'] or {'state': 'pending'}


def send(client, item, action):
    started = NOW()
    packet = {'item': item, 'action': 'status' if action == 'status_recheck' else 'submit'}
    reply = client.call(packet)
    return {key_: item[key_] for key_ in BINDING_FIELDS} | {
        'action': action, 'status': reply['state'] if reply else 'transport_unknown',
        'start_ns': started, 'end_ns': NOW(), 'worker_pid': mp.current_process().pid,
        'handle_sha256': hashlib.sha256(item['handle'].encode()).hexdigest(),
        'wire_item_fields': ';'.join(sorted(item)),
    }


def worker_main(connection, schedule, seed, starting, pipe):
    client = PipeClient(connection)
    rng = random.Random(seed)
    rows = []
    pipe.send(('ready', mp.current_process().pid))
    starting.wait()
    with ThreadPoolExecutor(max_workers=2) as callers:
        for item, duplicate in schedule:
            time.sleep(rng.uniform(.001, .006))
            second = callers.submit(send, client, item, 'concurrent_duplicate') if duplicate else None
            first = send(client, item, 'first_submission')
            rows.append(first)
            extra = second.result() if second else None
            if extra:
                rows.append(extra)
            if any(r and r['status'] in ('pending', 'transport_unknown') for r in (first, extra)):
                time.sleep(PENDING_SAMPLE)
                rows.append(send(client, item, 'status_recheck'))
    pipe.send(('done', rows))
    pipe.close()
    client.close()


def new_gateway_channel(ctx, gateway):
    service, remote = ctx.Pipe()

    def handle(packet, notify):
        if packet['action'] == 'status':
            return gateway.lookup(packet['item'])
        return gateway.submit(packet['item'], notify)

    service_thread = threading.Thread(target=serve, args=(service, handle, 4, gateway.errors), daemon=True)
    service_thread.start()
    return remote, service_thread


def run_round(ctx, gateway, worker_count, epoch, seed, item_count, delay):
    for scope in SCOPES:
        gateway.grant(scope, epoch)
    starting = ctx.Event()
    active = []
    observations = []
    try:
        for worker in range(worker_count):
            schedule = []
            for index in range(item_count):
                fault = FAULTS[(index // 2 + worker + epoch) % len(FAULTS)]
                item = gateway.issue(f'{epoch:04}-{worker:02}-{index:02}', SCOPES[index % 2], epoch,
                                     fault, 'natural', worker)
                schedule.append((item, fault == 'duplicate'))
            left, right = ctx.Pipe()
            remote, service_thread = new_gateway_channel(ctx, gateway)
            child = ctx.Process(target=worker_main, args=(remote, schedule,
                                seed + worker * 11939, starting, right))
            child.start()
            right.close()
            remote.close()
            active.append((child, left, service_thread))
        for child, pipe, _ in active:
            assert pipe.poll(20) and pipe.recv() == ('ready', child.pid)
        if epoch == 1:
            gateway.old_control = gateway.issue('retired-control', 'withdrawn', epoch, 'normal', 'control')

        def revoke_later():
            starting.wait()
            time.sleep(delay)
            gateway.revoke(epoch)

        writer = threading.Thread(target=revoke_later, daemon=True)
        writer.start()
        started = NOW()
        starting.set()
        deadline = time.monotonic() + 50
        for child, pipe, _ in active:
            assert pipe.poll(max(0, deadline - time.monotonic())), child.pid
            tag, detail = pipe.recv()
            assert tag == 'done'
            observations.extend(detail)
            child.join(timeout=5)
            assert child.exitcode == 0
        writer.join(max(0, deadline - time.monotonic()))
        assert not writer.is_alive(), 'Revocation did not publish within the cutoff'
        return observations, {'stage': 'natural', 'epoch': epoch, 'workers': worker_count,
                              'planned_delay_ns': int(delay * 1e9), 'started_ns': started,
                              'worker_pids': [child.pid for child, _, _ in active]}
    finally:
        for child, pipe, service_thread in active:
            pipe.close()
            if child.is_alive():
                child.terminate()
                child.join()
            service_thread.join(timeout=5)


def controls(ctx, gateway, final_epoch):
    gateway.grant('withdrawn', final_epoch)
    fresh = gateway.issue('regrant-control', 'withdrawn', final_epoch, 'normal', 'control')
    corrupted = gateway.issue('invalid-tag-control', 'withdrawn', final_epoch, 'normal', 'control')
    envelope = gateway.issued[corrupted['id']]
    gateway.issued[corrupted['id']] = replace(envelope, sealed=bytes([envelope.sealed[0] ^ 1]) + envelope.sealed[1:])
    remote, thread = new_gateway_channel(ctx, gateway)
    client = PipeClient(remote)
    try:
        return [send(client, item, label) for label, item in (
            ('retired_after_regrant', gateway.old_control), ('valid_regrant', fresh),
            ('binding_mismatch', fresh | {'recipient': 'incorrect-synthetic-recipient'}),
            ('cross_handle', fresh | {'handle': corrupted['handle']}),
            ('invalid_tag', corrupted), ('regrant_status', fresh),
        )]
    finally:
        assert client.call({'action': 'stop'}) == {'state': 'stopping'}
        client.close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    database = args.out / 'receipts.sqlite'
    journal = args.out / 'receiver_events.json'
    if database.exists():
        parser.error('--out must not already contain a receipts database')
    ctx = mp.get_context('spawn')
    parent, child = ctx.Pipe(duplex=False)
    gw_connection, rx_connection = ctx.Pipe()
    receiver = ctx.Process(target=receiver_main, args=(database, journal, rx_connection, child))
    receiver.start()
    child.close()
    rx_connection.close()
    try:
        assert parent.poll(15) and parent.recv() == 'ready'
        receipt_client = PipeClient(gw_connection)
        gateway = Gateway(receipt_client)
        gateway.errors = []
        rng = random.Random(SEED)
        rows, schedules = [], []
        for workers in ((2,) if args.smoke else WORKERS):
            for trial in range(1 if args.smoke else ROUNDS):
                epoch = len(schedules) + 1
                result, schedule = run_round(ctx, gateway, workers, epoch, SEED + epoch * 6211,
                                             ITEMS, rng.uniform(.025, .190))
                rows.extend(result)
                schedules.append(schedule)
                print(f'{workers} workers, round {trial + 1}: {len(result)} calls', flush=True)
        control_rows = controls(ctx, gateway, len(schedules) + 1)
        assert not gateway.errors, gateway.errors
        time.sleep(LATE_ORIGINAL + .020)
        assert receipt_client.call({'action': 'stop'}) == {'state': 'stopping'}
        receipt_client.close()
        receiver.join(timeout=10)
        assert receiver.exitcode == 0
        store_csv(args.out / 'requests.csv', rows)
        store_csv(args.out / 'controls.csv', control_rows)
        store_csv(args.out / 'gateway_events.csv', gateway.events)
        store_csv(args.out / 'receiver_events.csv', json.loads(journal.read_text(encoding='utf-8')))
        (args.out / 'manifest.json').write_text(json.dumps(gateway.manifest, indent=2), encoding='utf-8')
        (args.out / 'campaign.json').write_text(json.dumps({
            'seed': SEED, 'items': ITEMS, 'scenarios': FAULTS, 'scopes': SCOPES, 'smoke': args.smoke,
            'transport': 'inherited_multiprocessing_pipe',
            'receiver_pid': receiver.pid, 'gateway_pid': mp.current_process().pid, 'runs': schedules,
        }, indent=2), encoding='utf-8')
    finally:
        parent.close()
        if receiver.is_alive():
            receiver.terminate()
            receiver.join()


if __name__ == '__main__':
    main()
