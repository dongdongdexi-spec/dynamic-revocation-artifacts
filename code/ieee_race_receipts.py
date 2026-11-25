"""Local seeded race campaign with observed commits and idempotent rechecks."""

import argparse
import csv
import hashlib
import json
import multiprocessing as mp
import random
import socket
import socketserver
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ieee_scope_locks import ScopeRWLocks


NOW = time.perf_counter_ns
SCOPES = ('withdrawn', 'independent')
RECIPIENT = 'synthetic-loopback-recipient'
FAULTS = ('normal', 'precommit_failure', 'lost_ack', 'duplicate', 'late_original', 'query_outage')
SEND_TIMEOUT = .060
LATE_ORIGINAL = .180
LOOKUP_OUTAGE = .220
PENDING_SAMPLE = .030
MAX_ATTEMPTS = 2


def digest(body):
    return hashlib.sha256(body.encode()).hexdigest()


def key(item):
    return tuple(item[f] for f in ('id', 'scope', 'epoch', 'recipient', 'sha256'))


def line(stream, value):
    stream.write(json.dumps(value, separators=(',', ':')).encode() + b'\n')
    stream.flush()


def receive(stream):
    row = stream.readline(100_000)
    return json.loads(row) if row else None


def rpc(address, packet, timeout=15):
    try:
        with socket.create_connection(address, timeout=timeout) as peer:
            peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with peer.makefile('rwb') as stream:
                line(stream, packet)
                return receive(stream)
    except OSError:
        return None


def event(rows, name, item, **fields):
    rows.append({'t_ns': NOW(), 'event': name, 'id': item.get('id', ''),
                 'scope': item['scope'], 'epoch': item['epoch'], **fields})


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    request_queue_size = 128


class Receiver:
    def __init__(self, database):
        self.db = sqlite3.connect(database, check_same_thread=False, isolation_level=None)
        self.db.executescript('''
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE operations (id TEXT PRIMARY KEY, scope TEXT NOT NULL, epoch INT NOT NULL,
                recipient TEXT NOT NULL, sha256 TEXT NOT NULL);
            CREATE TABLE attempts (id TEXT NOT NULL, attempt INT NOT NULL, state TEXT NOT NULL,
                PRIMARY KEY(id, attempt));
            CREATE TABLE receipts (id TEXT PRIMARY KEY, scope TEXT NOT NULL, epoch INT NOT NULL,
                recipient TEXT NOT NULL, sha256 TEXT NOT NULL, body TEXT NOT NULL,
                attempt INT NOT NULL, inserted_ns INT NOT NULL);
        ''')
        self.guard = threading.Lock()
        self.events = []
        self.query_dark_until = {}

    def apply(self, packet):
        action = packet['action']
        item = packet['item']
        attempt = packet['attempt']
        fault = item['fault']
        if action == 'submit' and fault == 'late_original' and attempt == 1:
            event(self.events, 'original_handler_waiting', item, attempt=attempt)
            time.sleep(LATE_ORIGINAL)
        with self.guard:
            if action in ('lookup', 'fence') and NOW() < self.query_dark_until.get(item['id'], 0):
                event(self.events, 'query_reply_withheld', item, attempt=attempt, action=action)
                return None
            self.db.execute('BEGIN IMMEDIATE' if action in ('submit', 'fence') else 'BEGIN')
            try:
                result, kind = self.transaction(action, item, attempt)
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            # Sample after SQLite COMMIT and before exposing this result over the wire.
            event(self.events, kind, item, attempt=attempt, action=action)
            if kind == 'committed' and attempt == 1 and fault in ('lost_ack', 'query_outage'):
                if fault == 'query_outage':
                    self.query_dark_until[item['id']] = NOW() + int(LOOKUP_OUTAGE * 1e9)
                event(self.events, 'ack_suppressed', item, attempt=attempt)
                return None
            return result

    def transaction(self, action, item, attempt):
        fields = key(item)
        row = self.db.execute('SELECT * FROM operations WHERE id=?', (item['id'],)).fetchone()
        if item['recipient'] != RECIPIENT or (row is not None and row != fields):
            return {'state': 'conflict'}, 'rejected_binding'
        receipt = self.db.execute('SELECT attempt FROM receipts WHERE id=?', (item['id'],)).fetchone()
        status = self.db.execute('SELECT state FROM attempts WHERE id=? AND attempt=?',
                                 (item['id'], attempt)).fetchone()
        if receipt is not None:
            if status is not None and action == 'submit':
                return {'state': 'fenced'}, 'fenced_original_refused'
            return {'state': 'committed', 'attempt': receipt[0]}, 'existing_receipt'
        if status is not None:
            return {'state': 'fenced'}, 'fenced_original_refused' if action == 'submit' else 'existing_fence'
        if action == 'lookup':
            return {'state': 'absent'}, 'lookup_absent'
        if action == 'submit' and digest(item['body']) != item['sha256']:
            return {'state': 'conflict'}, 'rejected_binding'
        if row is None:
            self.db.execute('INSERT INTO operations VALUES (?,?,?,?,?)', fields)
        if action == 'fence' or (attempt == 1 and item['fault'] == 'precommit_failure'):
            self.db.execute('INSERT INTO attempts VALUES (?,?,?)', (item['id'], attempt, 'fenced'))
            return {'state': 'fenced'}, 'fence_persisted' if action == 'fence' else 'precommit_fenced'
        self.db.execute('INSERT INTO receipts VALUES (?,?,?,?,?,?,?,?)',
                        (*fields, item['body'], attempt, NOW()))
        return {'state': 'committed', 'attempt': attempt}, 'committed'


class ReceiverHandler(socketserver.StreamRequestHandler):
    def handle(self):
        packet = receive(self.rfile)
        if packet is None:
            return
        if packet['action'] == 'stop':
            line(self.wfile, {'state': 'stopping'})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        response = self.server.receiver.apply(packet)
        if response is not None:
            try:
                line(self.wfile, response)
            except OSError:
                pass


def receiver_main(database, events_path, ready):
    receiver = Receiver(database)
    server = TCPServer(('127.0.0.1', 0), ReceiverHandler)
    server.receiver = receiver
    ready.send(server.server_address)
    ready.close()
    with server:
        server.serve_forever(poll_interval=.02)
    events_path.write_text(json.dumps(receiver.events), encoding='utf-8')
    receiver.db.close()


class Gateway:
    def __init__(self, receiver):
        self.receiver = receiver
        self.locks = ScopeRWLocks(SCOPES)
        self.revoked = set()
        self.events = []
        self.register = threading.Lock()
        self.jobs = {}

    def revoke(self, epoch):
        item = {'scope': 'withdrawn', 'epoch': epoch}
        event(self.events, 'revoke_requested', item)
        with self.locks.write('withdrawn'):
            self.revoked.add(epoch)
            event(self.events, 'revoke_published', item)

    def resolve(self, item, attempt, answer, notify):
        if answer is not None and answer['state'] != 'absent':
            return answer
        event(self.events, 'uncertain', item, attempt=attempt)
        notify({'state': 'pending'})
        metadata = dict(zip(('id', 'scope', 'epoch', 'recipient', 'sha256'), key(item), strict=True))
        metadata['fault'] = item['fault']
        while True:
            answer = rpc(self.receiver, {'action': 'lookup', 'item': metadata, 'attempt': attempt})
            if answer is not None and answer['state'] == 'absent':
                event(self.events, 'lookup_absent_still_pending', item, attempt=attempt)
                answer = rpc(self.receiver, {'action': 'fence', 'item': metadata, 'attempt': attempt})
            if answer is not None and answer['state'] != 'absent':
                event(self.events, 'receipt_resolved', item, attempt=attempt, state=answer['state'])
                return answer
            event(self.events, 'lookup_unavailable_still_pending', item, attempt=attempt)
            time.sleep(.012)

    def submit(self, item, notify):
        with self.register:
            state = self.jobs.setdefault(item['id'], {'key': key(item), 'lock': threading.Lock(), 'state': None})
        if state['key'] != key(item) or digest(item['body']) != item['sha256']:
            return {'state': 'conflict'}
        with state['lock']:
            if state['state'] is not None:
                event(self.events, 'duplicate_returned_cached_status', item, state=state['state']['state'])
                return state['state']
            for attempt in range(1, MAX_ATTEMPTS + 1):
                with self.locks.read(item['scope']):
                    if item['scope'] == 'withdrawn' and item['epoch'] in self.revoked:
                        event(self.events, 'denied', item, attempt=attempt)
                        outcome = {'state': 'denied'}
                        break
                    event(self.events, 'authorized', item, attempt=attempt)
                    response = rpc(self.receiver, {'action': 'submit', 'item': item, 'attempt': attempt},
                                   timeout=SEND_TIMEOUT)
                    outcome = self.resolve(item, attempt, response, notify)
                    # Hold the scope lease until a durable receipt or an attempt fence.
                    event(self.events, 'lease_terminal', item, attempt=attempt, state=outcome['state'])
                    if outcome['state'] != 'fenced':
                        break
                time.sleep(.001)
            event(self.events, 'settled', item, state=outcome['state'])
            state['state'] = outcome
            return outcome

    def lookup(self, item):
        with self.register:
            state = self.jobs.get(item['id'])
        if state is None:
            return {'state': 'pending'}
        if state['key'] != key(item):
            return {'state': 'conflict'}
        with state['lock']:
            return state['state'] or {'state': 'pending'}


class GatewayHandler(socketserver.StreamRequestHandler):
    def handle(self):
        packet = receive(self.rfile)
        if packet is None:
            return
        notified = False

        def notify(result):
            nonlocal notified
            if not notified:
                notified = True
                try:
                    line(self.wfile, result)
                except OSError:
                    pass

        try:
            if packet.get('action') == 'status':
                result = self.server.gateway.lookup(packet['item'])
            else:
                result = self.server.gateway.submit(packet['item'], notify)
            notify(result)
        except BaseException as exc:
            self.server.errors.append(repr(exc))
            raise


def worker_main(address, worker, epoch, count, seed, starting, pipe):
    rng = random.Random(seed)
    rows = []
    pipe.send(('ready', mp.current_process().pid))
    starting.wait()
    with ThreadPoolExecutor(max_workers=2) as callers:
        for index in range(count):
            time.sleep(rng.uniform(.001, .006))
            scope = SCOPES[index % 2]
            fault = FAULTS[(index // 2 + worker + epoch) % len(FAULTS)]
            operation = f'{epoch:04}-{worker:02}-{index:02}'
            body = f'SYNTHETIC:{operation}:{rng.getrandbits(384):096x}'
            item = {'id': operation, 'scope': scope, 'epoch': epoch, 'recipient': RECIPIENT,
                    'sha256': digest(body), 'body': body, 'fault': fault}

            def send(action):
                started = NOW()
                if action == 'status_recheck':
                    metadata = {k: item[k] for k in ('id', 'scope', 'epoch', 'recipient', 'sha256')}
                    answer = rpc(address, {'action': 'status', 'item': metadata})
                else:
                    answer = rpc(address, {'item': item})
                status = answer['state'] if answer is not None else 'transport_unknown'
                return {'id': operation, 'epoch': epoch, 'scope': scope, 'fault': fault,
                        'action': action, 'status': status, 'start_ns': started, 'end_ns': NOW(),
                        'worker_pid': mp.current_process().pid, 'sha256': item['sha256']}

            duplicate = callers.submit(send, 'concurrent_duplicate') if fault == 'duplicate' else None
            first = send('first_submission')
            rows.append(first)
            second = duplicate.result() if duplicate else None
            if second:
                rows.append(second)
            if any(r and r['status'] in ('pending', 'transport_unknown') for r in (first, second)):
                time.sleep(PENDING_SAMPLE)
                rows.append(send('status_recheck'))
    pipe.send(('done', rows))
    pipe.close()


def run_round(ctx, server, workers, count, epoch, seed, delay):
    starting = ctx.Event()
    active = []
    for worker in range(workers):
        left, right = ctx.Pipe()
        child = ctx.Process(target=worker_main, args=(server.server_address, worker, epoch, count,
                            seed + worker * 11939, starting, right))
        child.start()
        right.close()
        active.append((child, left))
    for child, pipe in active:
        assert pipe.poll(20) and pipe.recv() == ('ready', child.pid)
    end = threading.Event()

    def revoke_later():
        starting.wait()
        time.sleep(delay)
        server.gateway.revoke(epoch)
        end.set()

    thread = threading.Thread(target=revoke_later, daemon=True)
    thread.start()
    started = NOW()
    starting.set()  # Align workload start only. There is no delivery-stage barrier.
    rows = []
    for child, pipe in active:
        assert pipe.poll(30), child.pid
        tag, detail = pipe.recv()
        assert tag == 'done'
        rows.extend(detail)
        child.join(timeout=5)
        assert child.exitcode == 0
        pipe.close()
    assert end.wait(15), 'Revocation failed to reach its serialized boundary'
    thread.join()
    return rows, {'epoch': epoch, 'workers': workers, 'planned_delay_ns': int(delay * 1e9), 'started_ns': started}


def store_csv(path, rows):
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--workers', default=[6, 16], nargs='+', type=int)
    p.add_argument('--rounds', default=4, type=int)
    p.add_argument('--items', default=18, type=int)
    p.add_argument('--seed', default=472019, type=int)
    args = p.parse_args()
    if min(args.workers + [args.items, args.rounds]) < 1:
        p.error('worker counts, rounds and items must be positive')
    args.out.mkdir(parents=True, exist_ok=True)
    database = args.out / 'receipts.sqlite'
    journal = args.out / 'receiver_events.json'
    if database.exists():
        p.error('--out must not already contain a receipts database')
    ctx = mp.get_context('spawn')
    parent, child = ctx.Pipe(duplex=False)
    receiver = ctx.Process(target=receiver_main, args=(database, journal, child))
    receiver.start()
    child.close()
    assert parent.poll(15)
    receiver_address = parent.recv()
    gateway = Gateway(receiver_address)
    with TCPServer(('127.0.0.1', 0), GatewayHandler) as server:
        server.gateway = gateway
        server.errors = []
        listener = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02})
        listener.start()
        rng = random.Random(args.seed)
        rows, schedules = [], []
        try:
            for count in args.workers:
                for trial in range(args.rounds):
                    epoch = len(schedules) + 1
                    delay = rng.uniform(.025, .190)
                    request_rows, schedule = run_round(ctx, server, count, args.items, epoch,
                                                       args.seed + epoch * 6211, delay)
                    rows.extend(request_rows)
                    schedules.append(schedule)
                    print(f'{count} workers, round {trial+1}: {len(request_rows)} calls', flush=True)
            assert not server.errors, server.errors
        finally:
            server.shutdown()
            listener.join()
            time.sleep(LATE_ORIGINAL + .020)
            assert rpc(receiver_address, {'action': 'stop'}) == {'state': 'stopping'}
            receiver.join(timeout=10)
            assert receiver.exitcode == 0
    store_csv(args.out / 'requests.csv', rows)
    store_csv(args.out / 'gateway_events.csv', gateway.events)
    receiver_events = json.loads(journal.read_text(encoding='utf-8'))
    store_csv(args.out / 'receiver_events.csv', receiver_events)
    journal.unlink()
    (args.out / 'campaign.json').write_text(json.dumps({'seed': args.seed, 'items': args.items,
        'scenarios': FAULTS, 'scope_names': SCOPES, 'pending_sample_ns': int(PENDING_SAMPLE * 1e9),
        'receiver_pid': receiver.pid, 'gateway_pid': mp.current_process().pid, 'runs': schedules}, indent=2),
        encoding='utf-8')


if __name__ == '__main__':
    main()
