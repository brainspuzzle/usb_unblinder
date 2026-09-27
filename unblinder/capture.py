"""Explicitly enabled native observation and bounded packet captures, without elevation."""
import atexit
import collections
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import sys
import threading
import time


class Capture:
    def __init__(self, root):
        self.root = Path(root) / 'captures'
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.jobs = {}
        self.messages = queue.Queue(maxsize=4096)
        self.dropped = 0
        self.recent_keys = collections.defaultdict(lambda: collections.deque(maxlen=40))
        atexit.register(self.stop_all)

    def interfaces(self):
        binary = shutil.which('tcpdump')
        if not binary: return []
        p = subprocess.run([binary, '-D'], capture_output=True, text=True, timeout=5)
        if p.returncode: raise RuntimeError(p.stderr.strip())
        return [m.group(1) for line in p.stdout.splitlines() if (m := re.match(r'\d+\.([^\s]+)', line))]

    def status(self):
        with self.lock:
            return {'jobs': {k: {'running': v['process'].poll() is None, 'exit_code': v['process'].poll(),
                                 'error': v.get('error', ''), 'file': v.get('file'),
                                 'started': v['started']} for k, v in self.jobs.items()},
                    'dropped_events': self.dropped}

    def start(self, kind, interface=None, keys=False):
        with self.lock:
            if kind in self.jobs and self.jobs[kind]['process'].poll() is None:
                raise ValueError('Collector is already running')
            self.prune()
            filename = None
            if kind == 'packets':
                if interface not in self.interfaces(): raise ValueError('Select an available capture interface')
                filename = f'capture-{time.time_ns()}.pcap'
                # 10 MB chunks, at most 3 chunks. No shell and no automatic sudo.
                args = [shutil.which('tcpdump'), '-i', interface, '-n', '-U', '-C', '10', '-W', '3',
                        '-w', str(self.root / filename)]
            elif kind == 'input':
                if sys.platform != 'darwin': raise ValueError('Native HID observation requires macOS')
                binary = Path(__file__).resolve().parents[1] / 'native/observe'
                if not binary.exists(): raise ValueError('Build native/observe with the README command first')
                args = [str(binary)] + (['--keys'] if keys else [])
            elif kind == 'security':
                if sys.platform != 'darwin': raise ValueError('Unified log collector requires macOS')
                args = ['/usr/bin/log', 'stream', '--style', 'ndjson', '--level', 'info', '--predicate',
                        'process == "sudo" OR process == "authd" OR process == "tccd" OR process == "screencapture"']
            else: raise ValueError('Unknown collector')
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    errors='replace', bufsize=1, umask=0o077)
            job = {'process': proc, 'started': time.time(), 'file': filename, 'error': ''}
            self.jobs[kind] = job
            threading.Thread(target=self.read, args=(kind, job), daemon=True).start()
            threading.Thread(target=self.errors, args=(job,), daemon=True).start()
            return self.status()

    def errors(self, job):
        for line in job['process'].stderr:
            with self.lock: job['error'] = (job['error'] + line)[-4000:]

    def enqueue(self, item):
        try: self.messages.put_nowait(item)
        except queue.Full: self.dropped += 1

    def read(self, kind, job):
        for line in job['process'].stdout:
            try: row = json.loads(line)
            except ValueError: continue
            if kind == 'security': row = {'category': 'security', 'wall': time.time(), 'data': row}
            self.enqueue(row)
            if row.get('category') == 'hid' and row['data'].get('pressed') and row['data'].get('page') == 7:
                key = str(row['data'].get('location_id'))
                times = self.recent_keys[key]
                times.append(row['wall'])
                if len(times) >= 20 and times[-1] - times[-20] < 0.5:
                    self.enqueue({'category': 'injection', 'wall': row['wall'], 'data': {
                        'reason': '20 key/button down events within 0.5 seconds; heuristic, not proof',
                        'device': row['data']}})
                    times.clear()

    def stop(self, kind):
        with self.lock:
            job = self.jobs.get(kind)
            if job and job['process'].poll() is None:
                job['process'].terminate()
                try: job['process'].wait(timeout=3)
                except subprocess.TimeoutExpired:
                    job['process'].kill()
                    job['process'].wait(timeout=3)
        return self.status()

    def stop_all(self):
        for kind in list(self.jobs): self.stop(kind)

    def prune(self):
        files = sorted(self.root.glob('capture-*.pcap*'), key=lambda p: p.stat().st_mtime, reverse=True)
        total = 0
        active = [j['file'] for j in self.jobs.values() if j.get('file') and j['process'].poll() is None]
        for path in files:
            stat = path.stat()
            total += stat.st_size
            if any(path.name.startswith(name) for name in active): continue
            if total > 200 * 1024 * 1024 or time.time() - stat.st_mtime > 7 * 86400:
                path.unlink(missing_ok=True)

    def files(self):
        return [{'name': p.name, 'size': p.stat().st_size} for p in sorted(self.root.glob('capture-*.pcap*')) if p.is_file()]
