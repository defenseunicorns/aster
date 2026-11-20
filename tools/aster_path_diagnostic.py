#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Opt-in bounded production Event impairment/resource diagnostic."""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import re
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from aster_lan_mvp import ConnectJsonClient, RpcError, read_token_file, canonical_event_id, OperatorError
from aster_mesh_playground import NumberedPublisher, RpcError as PublicationRpcError
from aster_path_delivery import OwnedDocker, ExecutionError, _run_command, _pinned_docker

LIB = '/usr/local/libexec/aster/'
# Complete local Python import closure, including the numbered publisher.
# Image-resident delivery entrypoints are instead bound by the immutable image ID.
HELPER_FILES = ('aster_path_diagnostic.py', 'aster_mesh_playground.py',
                'aster_lan_mvp.py', 'aster_path_delivery.py')


def verify_events(accepted, actual, *, deadline=None, exact=False):
    """Require nonvacuous matching content; optionally require identical ID sets."""
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError('admitted Events not delivered before deadline')
    if not accepted:
        raise ValueError('no accepted Events')
    if exact and accepted.keys() != actual.keys():
        raise ValueError('Event ID set mismatch')
    for identity, expected in accepted.items():
        observed = actual.get(identity, {})
        if any(observed.get(key) != expected.get(key) for key in ('id', 'logicalKey', 'payload')):
            raise ValueError('missing or mismatched Event: ' + identity)
    return len(accepted)


def query_all(client, maximum):
    events, marker = {}, 0
    for _ in range(maximum + 1):
        response = client.call('QueryEvents', {
            'topic': 'mesh.messages', 'scope': 'demo/playground',
            'includeDescendantScopes': False, 'afterAcceptanceMarker': str(marker), 'limit': 128})
        for event in response.get('events', []):
            events[event['id']] = event
        if len(events) > maximum:
            raise ValueError('query Event bound exceeded')
        if not response.get('hasMore', False):
            return events
        next_marker = int(response['scannedThrough'])
        if next_marker <= marker:
            raise ValueError('query made no progress')
        marker = next_marker
    raise ValueError('query page bound exceeded')


def netem_args(profile, delay, jitter, loss, rate, reorder):
    if profile == 'baseline':
        return []
    if profile == 'outage':
        return ['loss', '100%']
    if profile not in ('impaired', 'reorder'):
        raise ValueError('unknown profile')
    result = ['limit', '1000', 'delay', f'{delay}ms', f'{jitter}ms',
              'loss', f'{loss}%', 'rate', f'{rate}mbit']
    if profile == 'reorder':
        result += ['reorder', f'{reorder}%']
    return result


class Worker:
    """One persistent nonroot helper per endpoint; bounded line IPC."""
    def __init__(self, argv):
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, bufsize=0)
        self.buffer = b''

    def call(self, action, timeout=45, **arguments):
        self.process.stdin.write(json.dumps(dict(action=action, **arguments)).encode() + b'\n')
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b'\n' not in self.buffer:
                if not selector.select(max(0, deadline - time.monotonic())):
                    raise TimeoutError('worker response deadline: ' + action)
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise ValueError('worker closed during ' + action)
                self.buffer += chunk
                if len(self.buffer) > 16 * 1024 * 1024:
                    raise ValueError('worker response bound exceeded')
        line, self.buffer = self.buffer.split(b'\n', 1)
        response = json.loads(line)
        if 'error' in response:
            raise ValueError(response['error'])
        return response['result']

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process.stdout.close()


def sample(client):
    pid = int(Path('/clab/state/agent.pid').read_text())
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return {'monotonic': time.monotonic(), 'agent_pid': pid,
            'cpu_ticks': int(fields[11]) + int(fields[12]),
            'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
            'rss_bytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE'),
            'application_status': client.status(),
            'queue_label': 'application delivery backlog; not Iroh send queue'}


class DiagnosticPublisher(NumberedPublisher):
    """One serialized SDK journal per publishing lane, never operation-key replay."""
    def publish_event(self, key, payload):
        observed = {}

        def apply(intent, result, recovered, inserted):
            if intent.get('payload') != base64.b64encode(payload).decode():
                raise RpcError('recovered publication payload mismatch')
            if recovered and intent.get('logicalKey') != base64.b64encode(key).decode():
                raise RpcError('recovered publication logical key mismatch')
            identity = canonical_event_id(result['receipt']['eventId'])
            observed.update(id=identity, logicalKey=base64.b64encode(key).decode(),
                            payload=base64.b64encode(payload).decode())
            return identity

        try:
            response = self._run('publish', ['--topic', 'mesh.messages', '--scope', 'demo/playground',
                                             '--logical-key', key.decode('ascii')], payload, json_response=True)
            result = response['result']
            apply({'payload': base64.b64encode(payload).decode()}, result, False, response['inserted'])
            self._run('publication-ack', ['--sequence', str(result['operationSequence'])])
        except (PublicationRpcError, OperatorError, KeyError, TypeError, ValueError):
            # Recovery fences the old session and retries only its journaled
            # sequence/intent. CLI resource exhaustion alone is not a definite
            # rejection: it can also mean a response was lost after commit.
            try:
                self.recover(apply)
            except Exception as error:
                raise RpcError('numbered publication outcome unknown; original journal retained') from error
            if not observed:
                raise RpcError('numbered publication outcome unknown; original journal retained')
        return observed


class PublicationLanes:
    def __init__(self, root=Path('/clab/state')):
        self.root = root
        self.local = threading.local()
        self.lock = threading.Lock()
        self.next_lane = 0

    def publish_event(self, key, payload):
        if not hasattr(self.local, 'publisher'):
            with self.lock:
                lane = self.next_lane
                self.next_lane += 1
            publisher = DiagnosticPublisher(Path('/usr/local/bin/asterctl'),
                                            self.root / f'diagnostic-publication-{lane}.redb',
                                            f'path-diagnostic-{lane}')
            publisher.initialize()
            publisher.connect('http://127.0.0.1:8181', self.root / 'client.token')
            self.local.publisher = publisher
        return self.local.publisher.publish_event(key, payload)


def publish_one(client, key, size):
    raw_key = key.encode()
    payload = (raw_key + b':' + b'x' * size)[:size]
    return client.publish_event(raw_key, payload)


class Workload:
    """Bounded paced publishers and independent continuous consumption."""
    def __init__(self, client, subscription, prefix, count, rate, size, publisher=None):
        self.client, self.subscription = client, subscription
        self.publications = publisher if publisher is not None else client
        self.accepted, self.deliveries, self.rejected, self.errors = {}, {}, [], []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.done = False
        self.started = time.monotonic()
        self.finished = None
        self.max_schedule_lag = 0.0
        self.publisher = threading.Thread(target=self.publish_loop, args=(prefix, count, rate, size), daemon=True)
        self.consumer = threading.Thread(target=self.consume_loop, daemon=True)
        self.consumer.start()
        self.publisher.start()

    def publish_loop(self, prefix, count, rate, size):
        slots = threading.BoundedSemaphore(48)

        def publish(key):
            try:
                result = publish_one(self.publications, key, size)
                with self.lock:
                    if 'rejected' in result:
                        self.rejected.append(result)
                    else:
                        self.accepted[result['id']] = result
            except Exception as error:
                with self.lock:
                    self.errors.append(str(error))
            finally:
                slots.release()

        with ThreadPoolExecutor(max_workers=48) as executor:
            for index in range(count):
                due = self.started + index / rate
                if self.stop.wait(max(0, due - time.monotonic())):
                    break
                lag = max(0, time.monotonic() - due)
                self.max_schedule_lag = max(self.max_schedule_lag, lag)
                if lag > 1 or not slots.acquire(blocking=False):
                    with self.lock:
                        self.errors.append('bounded publisher could not maintain requested pace')
                    break
                executor.submit(publish, f'{prefix}-{index:06d}')
        with self.lock:
            self.done = True
            self.finished = time.monotonic()

    def consume_loop(self):
        try:
            while not self.stop.is_set():
                response = self.client.call('PollEvents', {'subscriptionId': self.subscription,
                                                          'deliveryLimit': 32, 'scanLimit': 1024})
                for delivery in response.get('deliveries', []):
                    event = delivery['event']
                    with self.lock:
                        self.deliveries[event['id']] = event
                    self.client.call('AcknowledgeEvent', {'subscriptionId': self.subscription, 'eventId': event['id']})
                    if self.stop.is_set():
                        return
                self.stop.wait(0.05)
        except Exception as error:
            with self.lock:
                self.errors.append(str(error))

    def snapshot(self):
        with self.lock:
            return {'accepted': dict(self.accepted), 'deliveries': dict(self.deliveries),
                    'rejected': list(self.rejected), 'errors': list(self.errors), 'done': self.done,
                    'started': self.started, 'finished': self.finished,
                    'max_schedule_lag_seconds': self.max_schedule_lag}

    def close(self):
        self.stop.set()
        self.publisher.join(10)
        self.consumer.join(10)
        if self.publisher.is_alive() or self.consumer.is_alive():
            raise TimeoutError('workload thread shutdown deadline')


def wait_stopped(pid):
    deadline = time.monotonic() + 10
    while True:
        try:
            state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            # procfs may report ESRCH as well as ENOENT during process exit.
            return
        if state == 'Z':
            return
        if time.monotonic() > deadline:
            raise TimeoutError('agent stop deadline')
        time.sleep(0.05)


def worker_main():
    client = ConnectJsonClient('http://127.0.0.1:8181',
                               read_token_file(Path('/clab/state/client.token')), timeout=30)
    subscription = None
    workload = None
    publications = PublicationLanes()
    while True:
        line = sys.stdin.readline(16385)
        if not line:
            break
        if len(line) > 16384:
            raise ValueError('worker request bound exceeded')
        try:
            request = json.loads(line)
            action = request['action']
            if action == 'status':
                result = sample(client)
            elif action == 'subscribe':
                subscription = client.subscribe(b'path-diagnostic', 'mesh.messages', 'demo/playground')['subscriptionId']
                result = subscription
            elif action == 'publish':
                result = publish_one(publications, request['key'], request['size'])
            elif action == 'start-workload':
                if workload is not None:
                    raise ValueError('workload already started')
                workload = Workload(client, subscription, request['prefix'], request['count'], request['rate'], request['size'], publications)
                result = {'started': workload.started}
            elif action == 'progress':
                result = workload.snapshot()
            elif action == 'end-workload':
                workload.close()
                result = workload.snapshot()
            elif action == 'poll':
                result = []
                response = client.call('PollEvents', {'subscriptionId': subscription,
                                                     'deliveryLimit': 128, 'scanLimit': 1024})
                for delivery in response.get('deliveries', []):
                    event = delivery['event']
                    result.append(event)
                    client.call('AcknowledgeEvent', {'subscriptionId': subscription, 'eventId': event['id']})
            elif action == 'query-witness':
                events, _ = client.query_events('mesh.messages', 'demo/playground', request['key'].encode())
                result = any(event['id'] == request['identity'] for event in events)
            elif action == 'query':
                result = query_all(client, request['maximum'])
            elif action == 'stop':
                if workload is not None:
                    workload.close()
                pid = int(Path('/clab/state/agent.pid').read_text())
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                wait_stopped(pid)
                result = {'stopped_pid': pid}
            elif action == 'peerless':
                spec = importlib.util.spec_from_file_location('delivery_agent', LIB + 'delivery-agent.py')
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                argv = module.agent_argv(request['role'])
                index = argv.index('--peer')
                del argv[index:index + 2]
                process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                Path('/clab/state/agent.pid').write_text(str(process.pid))
                result = {'pid': process.pid, 'argv': argv}
            else:
                raise ValueError('unknown helper action')
            print(json.dumps({'result': result}, separators=(',', ':')), flush=True)
        except Exception as error:
            print(json.dumps({'error': str(error)}), flush=True)


class OutageRestoration:
    """Sole network writer from loss application through scheduled restoration.

    configure is bounded Docker IPC, never a worker/application RPC. Joining this
    non-daemon owner precedes every subsequent network change and owned cleanup.
    Even an early controller failure retains the requested outage duration.
    """
    def __init__(self, configure, seconds, record, *, clock=time.monotonic,
                 wait=time.sleep, persist=lambda: None):
        self.configure, self.seconds, self.record = configure, seconds, record
        self.clock, self.wait, self.persist = clock, wait, persist
        self.thread = threading.Thread(target=self._run, name='outage-restoration')

    def arm(self, applied):
        # Called after BOTH replacement attempts, before any slow readback.
        if applied is not None:
            self.record.update(applied_monotonic=applied,
                               restore_target_monotonic=applied + self.seconds)
        self.thread.start()

    def start(self):
        self.record['apply_started_monotonic'] = self.clock()
        try:
            self.configure('outage', on_applied=self.arm)
        except (Exception, KeyboardInterrupt) as error:
            self.record['apply_error'] = str(error) or 'interrupted'
            if self.thread.ident is None:
                self.arm(None)
            raise
        self.check()
        self.require_active()

    def _run(self):
        try:
            target = self.record.get('restore_target_monotonic')
            if target is not None:
                self.wait(max(0, target - self.clock()))
        except Exception as error:
            self.record['restore_error'] = str(error)
        finally:
            self.record['restore_started_monotonic'] = self.clock()
            try:
                self.record['restored_monotonic'] = self.configure('baseline')
            except Exception as error:
                self.record['restore_error'] = str(error)
            try:
                self.persist()
            except Exception as error:
                self.record['evidence_error'] = str(error)

    def check(self):
        errors = [self.record[key] for key in ('apply_error', 'restore_error', 'evidence_error')
                  if key in self.record]
        if errors:
            raise ExecutionError('outage restoration: ' + '; '.join(errors))

    def finish(self):
        # At most the configured remaining outage plus bounded configure calls.
        # No cancellation race, daemon leak, duplicate restore or worker lock.
        if self.thread.ident is not None:
            self.thread.join()

    def require_active(self):
        if ('restore_started_monotonic' in self.record or
                self.clock() >= self.record['restore_target_monotonic']):
            raise ValueError('outage witness not verified before scheduled restore')


def run_profile(config, profile, report):
    """Own all containers; never issue a host networking command."""
    run = _pinned_docker(_run_command)
    docker = shutil.which('docker')
    directory = Path(tempfile.mkdtemp(prefix='aster-diagnostic-'))
    owned = OwnedDocker(docker, directory, _run_command, image=getattr(config, 'image', 'aster-path-delivery:local'))
    workers, nodes, setup = {}, {}, {}
    provision = None
    outage = None
    lab = directory / 'lab'
    lab.mkdir(mode=0o700)
    report.update(profile=profile, status='running', phases=[], samples=[], accepted={},
                  rejected={}, deliveries={}, qdiscs=[], ownership_directory=str(directory))
    start = time.monotonic()

    def phase(name):
        report['phases'].append({'phase': name, 'elapsed': time.monotonic() - start})
        (config.output / (profile + '.json')).write_text(json.dumps(report) + '\n')
        print(json.dumps({'profile': profile, **report['phases'][-1]}), flush=True)

    def command(*args, timeout=30):
        return run([docker, *args], timeout)

    def execute(cid, *args, timeout=30):
        return command('exec', cid, *args, timeout=timeout)

    def create(role, options, argv, caps=()):
        cid = owned.create(role, options, argv, caps)
        if hasattr(config, 'image'):
            actual = command('inspect', '--format', '{{.Image}}', cid).decode().strip()
            report.setdefault('all_container_image_ids', {})[role] = actual
            if actual != config.image:
                raise ExecutionError('container image identity mismatch')
        command('start', cid)
        return cid

    def configure(which, *, on_applied=None):
        args = netem_args(which, config.delay_ms, config.jitter_ms, config.loss_percent,
                          config.rate_mbit, config.reorder_percent)
        rows, texts, changes, errors = [], [], [], []
        for interface in ('wan1', 'wan2'):
            change = {'interface': interface, 'started_monotonic': time.monotonic()}
            changes.append(change)
            try:
                # A zero-delay netem keeps replacement/readback uniform.
                execute(setup['wan'], 'tc', 'qdisc', 'replace', 'dev', interface,
                        'root', 'netem', *(args or ['delay', '0ms']), timeout=5)
                change['applied_monotonic'] = time.monotonic()
            except Exception as error:
                change['error'] = str(error)
                errors.append(interface + ': ' + str(error))
        # Attempt BOTH egresses even if one fails, without retrying a command.
        # Arm restoration BEFORE readback. Use the first egress application as
        # the deadline origin; retain both interface timings in the receipt.
        if on_applied is not None:
            on_applied(None if errors else changes[0]['applied_monotonic'])
        for interface in ('wan1', 'wan2'):
            try:
                rows.append(json.loads(execute(setup['wan'], 'tc', '-j', '-s', 'qdisc', 'show', 'dev', interface, timeout=5)))
                texts.append(execute(setup['wan'], 'tc', 'qdisc', 'show', 'dev', interface, timeout=5).decode())
            except Exception as error:
                errors.append(interface + ' readback: ' + str(error))
        report['qdiscs'].append({'elapsed': time.monotonic() - start, 'profile': which,
                                 'arguments': args, 'rows': rows, 'text': texts,
                                 'changes': changes, 'errors': errors})
        if errors:
            raise ExecutionError('; '.join(errors))
        if which == 'outage' and any('loss 100%' not in text for text in texts):
            raise ValueError('100 percent outage readback failed')
        if which == 'baseline' and any('loss' in text for text in texts):
            raise ValueError('baseline restoration readback still contains loss')
        return changes[-1]['applied_monotonic']

    def consume(action='progress'):
        done = True
        errors = []
        for role, worker in workers.items():
            progress = worker.call(action)
            report['accepted'][role].update(progress['accepted'])
            report['deliveries'][role].update(progress['deliveries'])
            report['rejected'][role] = progress['rejected']
            report.setdefault('workload_timing', {})[role] = {key: progress[key] for key in
                ('done', 'started', 'finished', 'max_schedule_lag_seconds')}
            done = done and progress['done']
            errors.extend(role + ': ' + error for error in progress['errors'])
        if errors:
            raise ValueError('; '.join(errors))
        return done

    def publish(role, key):
        event = workers[role].call('publish', key=key, size=config.payload_bytes)
        if 'rejected' in event:
            report['rejected'][role].append({'key': key, **event})
            return None
        report['accepted'][role][event['id']] = event
        return event['id']

    def sample_all():
        report['samples'].append({role: worker.call('status') for role, worker in workers.items()})
        (config.output / (profile + '.json')).write_text(json.dumps(report) + '\n')
        print(json.dumps({'profile': profile, 'elapsed': time.monotonic() - start,
                          'accepted': {role: len(events) for role, events in report['accepted'].items()},
                          'rejected': {role: len(events) for role, events in report['rejected'].items()},
                          'delivered': {role: len(events) for role, events in report['deliveries'].items()}}), flush=True)

    def ready(worker):
        deadline = time.monotonic() + 30
        while True:
            try:
                return worker.call('status')
            except ValueError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)

    previous_alarm = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise ExecutionError('diagnostic profile deadline exceeded')

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(getattr(config, 'duration_seconds', 60) +
                 getattr(config, 'restore_deadline_seconds', 120) + 420)
    try:
        phase('setup')
        wan = create('wan', ['--network', 'none', '--sysctl', 'net.ipv4.ip_forward=1'], ['sleep', '1800'])
        helper_directory = getattr(config, 'helper_directory', Path(__file__).resolve().parent)
        helper_mounts = []
        for name in HELPER_FILES:
            target = 'diagnostic.py' if name == 'aster_path_diagnostic.py' else name
            helper_mounts += ['--volume', str(helper_directory / name) + ':/' + target + ':ro']
        for role in ('node-a', 'node-b'):
            (lab / role).mkdir(mode=0o700)
            nodes[role] = create(role, ['--network', 'none', '--volume', str(lab / role) + ':/clab',
                                      *helper_mounts], ['sleep', '1800'])
            report['accepted'][role], report['deliveries'][role], report['rejected'][role] = {}, {}, []
        provision = create('provision', ['--network', 'none', '--volume', str(lab) + ':/lab'],
                           ['sleep', '1800'], ('CHOWN',))
        execute(provision, 'python3', '-c',
                "import os; os.chown('/lab',0,0); "
                "[os.chown('/lab/'+r,0,0) for r in ('node-a','node-b')]")
        execute(provision, LIB + 'delivery-provision.py')
        wan_pid = int(command('inspect', '--format', '{{.State.Pid}}', wan))
        if wan_pid <= 1:
            raise ValueError('WAN namespace holder is not running')
        host_netns = os.stat('/proc/self/ns/net').st_ino
        # Daemon resolves the owned running container's namespace bind. No host
        # namespace entry, SYS_ADMIN, privileged container, or host qdisc.
        for segment, (role, cid) in enumerate(nodes.items(), 1):
            setup[role] = create(role + '-setup', ['--network', 'container:' + cid,
                '--volume', f'/proc/{wan_pid}/ns/net:/target:ro'], ['sleep', '1800'], ('NET_ADMIN',))
            if int(command('inspect', '--format', '{{.State.Pid}}', wan)) != wan_pid:
                raise ValueError('WAN namespace identity changed')
            namespace_inodes = json.loads(execute(setup[role], 'python3', '-c',
                "import os,json; print(json.dumps([os.stat('/target').st_ino,os.stat('/proc/self/ns/net').st_ino]))"))
            if len(set([host_netns, *namespace_inodes])) != 3:
                raise ValueError('network namespaces are not isolated')
            execute(setup[role], 'ip', 'link', 'add', 'eth0', 'type', 'veth',
                    'peer', 'name', f'wan{segment}', 'netns', '/target')
            execute(setup[role], LIB + 'delivery-network-init.py', role)
        setup['wan'] = create('wan-setup', ['--network', 'container:' + wan], ['sleep', '1800'], ('NET_ADMIN',))
        for segment in (1, 2):
            execute(setup['wan'], 'ip', 'addr', 'add', f'10.77.{segment}.1/29', 'dev', f'wan{segment}')
            execute(setup['wan'], 'ip', 'link', 'set', f'wan{segment}', 'up')
        configure('baseline' if profile == 'outage' else profile)
        report['production_binary_sha256'] = execute(nodes['node-a'], 'sha256sum', '/usr/local/bin/aster-agent').decode().split()[0]
        report['container_image_ids'] = {role: command('inspect', '--format', '{{.Image}}', cid).decode().strip()
                                         for role, cid in nodes.items()}
        for role, cid in nodes.items():
            command('exec', '--detach', cid, LIB + 'delivery-agent.py', role)
            workers[role] = Worker([docker, '--host', 'unix:///var/run/docker.sock', 'exec', '-i', cid,
                                   'env', 'PYTHONPATH=' + LIB, 'python3', '/diagnostic.py', '--worker'])
            ready(workers[role])
            execute(cid, LIB + 'delivery-agent.py', 'verify', role)
            workers[role].call('subscribe')
        execute(wan, LIB + 'delivery-agent.py', 'verify', 'wan')
        report['capabilities'] = 'verified holders and initial agent PIDs'
        sample_all()
        phase('publish-and-continuous-consume')
        publish_start = time.monotonic()
        count = int(config.duration_seconds * config.events_per_second)
        outage_start = None
        restored = None
        witnesses = {}
        next_sample = publish_start
        for role, worker in workers.items():
            worker.call('start-workload', prefix=f'{profile}-{role}', count=count,
                        rate=config.events_per_second, size=config.payload_bytes)
        while True:
            if time.monotonic() - publish_start > config.duration_seconds + 15:
                raise TimeoutError('paced publication completion deadline')
            if profile == 'outage' and outage_start is None and time.monotonic() - publish_start >= config.outage_at_seconds:
                report['outage_restoration'] = {}

                def persist_restoration():
                    (config.output / 'outage-restoration.json').write_text(
                        json.dumps(report['outage_restoration']) + '\n')

                outage = OutageRestoration(configure, config.outage_seconds,
                    report['outage_restoration'], persist=persist_restoration)
                outage.start()
                outage_start = report['outage_restoration']['applied_monotonic']
                report['outage_witness'] = {'ids': witnesses, 'absent_before_restore': False,
                                            'publications': {}}
                phase('confirmed-outage-witness')
                for role in workers:
                    timing = {'started_monotonic': time.monotonic()}
                    report['outage_witness']['publications'][role] = timing
                    try:
                        witnesses[role] = publish(role, f'{profile}-{role}-witness')
                    finally:
                        timing['finished_monotonic'] = time.monotonic()
                    if witnesses[role] is None:
                        raise ValueError('outage witness rejected')
                # Keep workload/unknown-outcome failures primary. The final
                # receipt separately records any missing negative evidence.
                consume()
                outage.require_active()
                for role, identity in witnesses.items():
                    other = 'node-b' if role == 'node-a' else 'node-a'
                    present = workers[other].call('query-witness', key=f'{profile}-{role}-witness', identity=identity)
                    outage.require_active()
                    if present or identity in report['deliveries'][other]:
                        raise ValueError('outage witness reached peer before restore')
                report['outage_witness'].update(absent_before_restore=True,
                    verified_monotonic=time.monotonic())
            if outage is not None:
                outage.check()
                restored = report['outage_restoration'].get('restored_monotonic')
            done = consume()
            if time.monotonic() >= next_sample:
                sample_all()
                next_sample = time.monotonic() + config.sample_seconds
            if done:
                if outage is not None:
                    outage.finish()
                    outage.check()
                    restored = report['outage_restoration'].get('restored_monotonic')
                break
            time.sleep(0.25)
        report['publish_elapsed_seconds'] = time.monotonic() - publish_start
        for role in workers:
            expected_attempts = count + (1 if role in witnesses else 0)
            if len(report['accepted'][role]) + len(report['rejected'][role]) != expected_attempts:
                raise ValueError('publication attempt accounting mismatch')
        if profile == 'outage' and restored is None:
            raise ValueError('workload ended before outage restore')
        if outage is not None:
            outage.finish()
            outage.check()
        phase('drain')
        deadline = (restored or time.monotonic()) + config.restore_deadline_seconds
        while True:
            consume()
            complete = True
            for role in workers:
                other = 'node-b' if role == 'node-a' else 'node-a'
                try:
                    verify_events(report['accepted'][role], report['deliveries'][other], deadline=deadline)
                except ValueError:
                    complete = False
            if complete:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('admitted Events not delivered before deadline')
            if time.monotonic() >= next_sample:
                sample_all()
                next_sample = time.monotonic() + config.sample_seconds
            time.sleep(0.1)
        report['restore_delivery_seconds'] = time.monotonic() - restored if restored else None
        sample_all()
        report['final_qdisc_stats'] = {interface: json.loads(execute(setup['wan'], 'tc', '-j', '-s',
            'qdisc', 'show', 'dev', interface)) for interface in ('wan1', 'wan2')}
        phase('stop-both')
        # Drain observes deliveries before their acknowledgement RPC returns.
        # Join both workloads and check their final errors before reopening.
        consume('end-workload')
        for worker in workers.values():
            worker.call('stop')
        # Keep both WAN egresses completely cut across peerless reopen too.
        configure('outage')
        phase('peerless-reopen')
        expected = {identity: event for events in report['accepted'].values() for identity, event in events.items()}
        report['peerless'] = {}
        for role, worker in workers.items():
            restart = worker.call('peerless', role=role)
            ready(worker)
            execute(nodes[role], LIB + 'delivery-agent.py', 'verify', role)
            actual = worker.call('query', maximum=count * 2 + 2, timeout=180)
            report['peerless'][role] = {'restart': restart, 'exact_events': verify_events(expected, actual, exact=True)}
        sample_all()
        report['status'] = 'pass'
    except (Exception, KeyboardInterrupt) as error:
        report['status'] = 'fail'
        report['error'] = str(error) or 'interrupted'
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_alarm)
        cleanup_errors = []
        if outage is not None:
            # SIGTERM/interrupt during application IPC cannot bypass restoration.
            # Defer further interrupts until the bounded network owner is joined.
            previous_term = signal.signal(signal.SIGTERM, signal.SIG_IGN)
            previous_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                outage.finish()
                witness = report.get('outage_witness')
                if witness is not None and not witness['absent_before_restore']:
                    witness['error'] = 'outage witness not verified before scheduled restore'
                restored_at = report['outage_restoration'].get('restored_monotonic')
                if restored_at is not None:
                    report['phases'].append({'phase': 'restored', 'elapsed': restored_at - start})
                    report['phases'].sort(key=lambda row: row['elapsed'])
                try:
                    outage.check()
                except Exception as error:
                    report['restoration_error'] = str(error)
                    report['status'] = 'fail'
                    report.setdefault('error', str(error))
            finally:
                signal.signal(signal.SIGTERM, previous_term)
                signal.signal(signal.SIGINT, previous_int)
        try:
            phase('cleanup')
        except OSError:
            cleanup_errors.append('progress-output')
        for worker in workers.values():
            try:
                worker.call('stop')
            except Exception:
                pass
            try:
                worker.close()
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        # CHOWN-only provisioning helper reclaims only its private bind tree.
        # No host privilege or additional daemon capability is needed.
        if provision is not None:
            try:
                execute(provision, 'python3', '-c',
                        "import os,pathlib\n"
                        "def purge(p):\n"
                        " os.chown(p,0,0,follow_symlinks=False)\n"
                        " if p.is_dir() and not p.is_symlink():\n"
                        "  os.chmod(p,0o700)\n"
                        "  for c in p.iterdir(): purge(c)\n"
                        "  p.rmdir()\n"
                        " else: p.unlink()\n"
                        "p=pathlib.Path('/lab')\n"
                        "os.chown(p,0,0); os.chmod(p,0o700)\n"
                        "for c in p.iterdir(): purge(c)\n"
                        f"os.chown(p,{os.getuid()},{os.getgid()})\n")
            except Exception:
                cleanup_errors.append('credential-cleanup')
        cleanup_errors.extend(owned.cleanup())
        if not cleanup_errors:
            try:
                shutil.rmtree(directory)
            except OSError:
                cleanup_errors.append('directory-cleanup')
        report['cleanup_errors'] = cleanup_errors
        report['elapsed_seconds'] = time.monotonic() - start
        if cleanup_errors:
            report['status'] = 'fail'
        (config.output / (profile + '.json')).write_text(json.dumps(report) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--image', default='aster-path-delivery:local')
    parser.add_argument('--build-kind', choices=['canonical-release', 'local-debug', 'local-release'], default='canonical-release')
    parser.add_argument('--profiles', nargs='+', choices=['baseline', 'impaired', 'reorder', 'outage'],
                        default=['baseline', 'impaired', 'reorder', 'outage'])
    bounds = {'duration-seconds': (60, 1, 300), 'events-per-second': (10, 1, 20),
              'payload-bytes': (1024, 1, 4096), 'delay-ms': (40, 1, 1000),
              'jitter-ms': (5, 0, 100), 'loss-percent': (1, 0, 50),
              'rate-mbit': (100, 1, 1000), 'reorder-percent': (10, 0, 100),
              'outage-seconds': (10, 1, 60), 'outage-at-seconds': (20, 0, 120),
              'restore-deadline-seconds': (120, 1, 300), 'sample-seconds': (5, 1, 30)}
    for name, (default, _, _) in bounds.items():
        parser.add_argument('--' + name, type=int, default=default)
    config = parser.parse_args()
    if config.worker:
        worker_main()
        return 0
    if config.output is None:
        parser.error('--output is required')
    for name, (_, low, high) in bounds.items():
        if not low <= getattr(config, name.replace('-', '_')) <= high:
            parser.error(name + ' outside supported bounds')
    if config.duration_seconds * config.events_per_second * (config.payload_bytes + 1024) > 4 * 1024 * 1024:
        parser.error('combined workload exceeds bounded receipt/IPC budget')
    if 'outage' in config.profiles and config.outage_at_seconds + config.outage_seconds >= config.duration_seconds:
        parser.error('outage must finish within publication window')
    os.umask(0o077)

    def interrupted(_signum, _frame):
        raise ExecutionError('diagnostic terminated')

    signal.signal(signal.SIGTERM, interrupted)
    config.output.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'aster-path-diagnostic/v1', 'status': 'running',
              'configuration': {k: v for k, v in vars(config).items() if k not in ('worker', 'output')},
              'profiles': [], 'limitation': 'one-host Docker; no physical or production acceptance claim'}
    run = _pinned_docker(_run_command)
    root = Path(__file__).resolve().parent.parent
    try:
        report['image_id'] = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', config.image], 5).decode().strip()
        if re.fullmatch(r'sha256:[0-9a-f]{64}', report['image_id']) is None:
            raise ExecutionError('invalid immutable image ID')
        config.image = report['image_id']
        with tempfile.TemporaryDirectory(prefix='aster-diagnostic-helpers-') as helpers:
            config.helper_directory = Path(helpers)
            for name in HELPER_FILES:
                destination = config.helper_directory / name
                destination.write_bytes((root / 'tools' / name).read_bytes())
            for profile in config.profiles:
                row = {}
                report['profiles'].append(row)
                run_profile(config, profile, row)
                (config.output / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
            report['status'] = 'pass' if all(row['status'] == 'pass' for row in report['profiles']) else 'fail'
    except Exception as error:
        report.update(status='fail', error=str(error))
    finally:
        (config.output / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'receipt': str(config.output / 'receipt.json')}))
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
