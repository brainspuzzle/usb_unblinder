"""Continuous, bounded, observational telemetry. Never infer USB causation from timing."""
import hashlib
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
import uuid

from .forensics import context
from .util import now_iso


def command(args, timeout=5, empty_codes=()):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                       errors='replace', env={**os.environ, 'LC_ALL': 'C'})
    if p.returncode and p.returncode not in empty_codes:
        raise RuntimeError(p.stderr.strip()[:400] or f'exit {p.returncode}')
    return p.stdout


class Collectors:
    def __init__(self):
        home = Path.home()
        self.roots = [home / 'Downloads', home / 'Desktop', Path('/private/tmp' if context.MAC else '/tmp')]
        self.persistence = [home / 'Library/LaunchAgents', Path('/Library/LaunchAgents'),
                            Path('/Library/LaunchDaemons')]
        self.persistence += [home / n for n in ('.zshrc', '.zprofile', '.bashrc', '.bash_profile')]
        self.persistence += [home / 'Library/Application Support/com.apple.backgroundtaskmanagementagent',
                             Path('/var/db/com.apple.backgroundtaskmanagement')] 
        self.excluded = Path(__file__).resolve().parents[1]

    def processes(self):
        rows = context.processes()
        excluded = context.own_descendants(rows, time.time())
        return {f"{p['pid']}:{p['start']}": p for p in rows if p['pid'] not in excluded}

    def network(self):
        if not shutil.which('lsof'):
            raise RuntimeError('lsof unavailable; process socket collection unavailable')
        out = command(['lsof', '-nP', '-i', '-FpcnPt'], empty_codes=(1,))
        result, pid, name, proto = {}, None, '', ''
        for line in out.splitlines():
            if line.startswith('p'): pid = line[1:]
            elif line.startswith('c'): name = line[1:]
            elif line.startswith('P'): proto = line[1:]
            elif line.startswith('n') and pid:
                value = dict(pid=int(pid), process=name, protocol=proto, endpoint=line[1:])
                result[f'{pid}:{proto}:{line[1:]}'] = value
        return result

    def traffic(self):
        if context.MAC:
            lines = command(['netstat', '-ibn']).splitlines()
            if not lines: return {}
            header = lines[0].split()
            result = {}
            for line in lines[1:]:
                fields = line.split()
                if len(fields) < len(header) or not fields[2].startswith('<Link#'):
                    continue
                row = dict(zip(header, fields))
                result[row['Name']] = {k: int(row[k]) for k in ('Ibytes', 'Obytes', 'Ipkts', 'Opkts')}
            return result
        if context.LINUX:
            result = {}
            for path in Path('/sys/class/net').iterdir():
                result[path.name] = {key: int((path / 'statistics' / filename).read_text())
                                    for key, filename in [('Ibytes','rx_bytes'),('Obytes','tx_bytes'),
                                                          ('Ipkts','rx_packets'),('Opkts','tx_packets')]}
            return result
        raise RuntimeError('Interface traffic counters unavailable on this platform')

    def files(self, persistence=False):
        result, errors = {}, []
        roots = self.persistence if persistence else self.roots
        budget = 12000
        def inspect(path):
            nonlocal budget
            if budget <= 0:
                return
            budget -= 1
            try:
                if path.is_symlink() or path == self.excluded or self.excluded in path.parents:
                    return
                s = path.stat()
                if path.is_dir():
                    for child in path.iterdir():
                        inspect(child)
                        if budget <= 0: break
                elif path.is_file():
                    row = dict(path=str(path), size=s.st_size, mtime_ns=s.st_mtime_ns,
                               inode=s.st_ino, mode=s.st_mode)
                    if persistence and s.st_size <= 1024 * 1024:
                        row['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                    result[str(path)] = row
            except FileNotFoundError:
                pass
            except OSError as e:
                errors.append(f'{path}: {e.strerror}')
        for root in roots: inspect(root)
        if budget <= 0: errors.append('12000-entry scan limit reached')
        if errors:
            raise PartialSample(result, errors[:10])
        return result

    def persistence_state(self):
        rows = self.files(True)
        if shutil.which('crontab'):
            p = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=5)
            if p.returncode == 0:
                rows['crontab'] = {'content': p.stdout}
            elif 'no crontab' not in p.stderr.lower():
                raise PartialSample(rows, [p.stderr.strip() or 'crontab unavailable'])
        return rows

    def foreground(self):
        if not context.MAC:
            raise RuntimeError('Foreground application collector requires macOS')
        # AppKit does not request Apple Events automation or read window titles.
        try:
            from AppKit import NSWorkspace
        except ImportError:
            raise RuntimeError('Install pyobjc-framework-Cocoa to observe foreground applications')
        app = NSWorkspace.sharedWorkspace().frontmostApplication()
        return {'active': {'pid': app.processIdentifier(), 'name': str(app.localizedName()),
                           'bundle': str(app.bundleIdentifier())}}

    def system(self):
        row = context.sample()
        values = {k: v for k, v in row.items() if k not in ('time', 'wall', 'hid_idle')}
        errors = [f'{k}: {v["error"]}' for k, v in values.items() if isinstance(v, dict) and 'error' in v]
        if errors:
            raise PartialSample({k: v for k, v in values.items() if not isinstance(v, dict) or 'error' not in v}, errors)
        return values


class PartialSample(Exception):
    def __init__(self, data, errors):
        self.data, self.errors = data, errors
        super().__init__('; '.join(errors))


class Telemetry:
    def __init__(self, monitor, interval=2, grace=60):
        self.monitor, self.store = monitor, monitor.store
        self.interval, self.grace = interval, grace
        self.collectors = Collectors()
        self.events = queue.Queue(maxsize=2048)
        self.active, self.previous, self.health = {}, {}, {}
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.started = False
        self.dropped = 0
        self.config_path = Path(monitor.capture.root).parent / 'telemetry-settings.json' if getattr(monitor, 'capture', None) else None
        if self.config_path and self.config_path.exists():
            try:
                self.configure(json.loads(self.config_path.read_text()), save=False)
            except (ValueError, OSError, TypeError):
                self.health['settings'] = {'state': 'error', 'error': 'Invalid settings file; defaults used'}
        self.sources = {'process': self.collectors.processes, 'network': self.collectors.network,
                        'file': self.collectors.files, 'persistence': self.collectors.persistence_state,
                        'foreground': self.collectors.foreground, 'system': self.collectors.system,
                        'traffic': self.collectors.traffic}

    def configure(self, body, save=True):
        interval = float(body.get('interval_seconds', self.interval))
        grace = float(body.get('post_disconnect_seconds', self.grace))
        if not 0.5 <= interval <= 300 or not 0 <= grace <= 3600:
            raise ValueError('Interval must be 0.5–300 seconds; post-disconnect time 0–3600 seconds')
        roots = body.get('file_roots', [str(p) for p in self.collectors.roots])
        if not isinstance(roots, list) or len(roots) > 20 or not all(isinstance(p, str) and Path(p).expanduser().is_absolute() for p in roots):
            raise ValueError('Provide up to 20 absolute directory paths')
        resolved = [Path(p).expanduser().resolve() for p in roots]
        if any(not p.is_dir() for p in resolved):
            raise ValueError('Each watched root must be an existing directory')
        self.interval, self.grace = interval, grace
        self.collectors.roots = resolved
        # A different scope needs a fresh baseline, not synthetic deletions.
        self.previous.pop('file', None)
        if save and self.config_path:
            data = dict(interval_seconds=interval, post_disconnect_seconds=grace, file_roots=[str(p) for p in resolved])
            self.config_path.write_text(json.dumps(data, indent=2))
            self.config_path.chmod(0o600)
        return self.capabilities()

    def start(self):
        if self.started: return
        self.started = True
        threading.Thread(target=self.run, name='continuous-telemetry', daemon=True).start()

    def on_event(self, ev):
        if ev.get('type') in ('snapshot', 'connected', 'removed', 'identity_changed'):
            try: self.events.put_nowait(ev)
            except queue.Full: self.dropped += 1

    def capabilities(self):
        with self.lock:
            return {'interval_seconds': self.interval, 'post_disconnect_seconds': self.grace,
                    'sources': dict(self.health), 'dropped_usb_events': self.dropped,
                    'limitations': ['System activity is temporal correlation, not USB attribution.',
                     'Polling can miss short-lived processes, connections and file changes.',
                     'File renames appear as delete/create; file writers are not attributed.',
                     'Socket visibility is limited by current user permissions.',
                     'Native HID and security logs are opt-in; window titles are not collected. Login-item files are watched, not a complete enumeration.',
                     'Packet capture is opt-in through the capture controls.'],
                    'file_roots': [str(p) for p in self.collectors.roots]}

    def record(self, sid, category, action, data, level='info', attribution='temporal', wall=None, precision='observed_at_poll'):
        session = self.active[sid]
        wall = time.time() if wall is None else wall
        from datetime import datetime, timezone
        if category == 'network' and isinstance(data.get('after'), dict):
            pid = data['after'].get('pid')
            proc = next((p for p in self.previous.get('process', {}).values() if p['pid'] == pid), None)
            data = {**data, 'process': proc, 'process_started_after_connect':
                    bool(proc and proc.get('start', 0) >= session['wall'])}
        if category == 'traffic' and isinstance(data.get('before'), dict) and isinstance(data.get('after'), dict):
            data = {**data, 'delta': {k: max(0, v - data['before'].get(k, v)) for k, v in data['after'].items()},
                    'scope': 'interface_total_not_per_process'}
        ev = {'session_id': sid, 'time': datetime.fromtimestamp(wall, timezone.utc).isoformat(timespec='milliseconds'), 'wall': wall,
              'elapsed': round(wall - session['wall'], 3), 'category': category,
              'action': action, 'data': data, 'level': level, 'attribution': attribution,
              'precision': precision, 'source': category}
        self.store.add_observation(ev)
        self.monitor.emit({'type': 'telemetry', **ev}, persist=False)

    @staticmethod
    def event_wall(ev):
        from datetime import datetime
        try:
            return datetime.fromisoformat(ev['time'].replace('Z', '+00:00')).timestamp()
        except (KeyError, ValueError):
            return time.time()

    def usb_events(self):
        while True:
            try: ev = self.events.get_nowait()
            except queue.Empty: break
            kind = ev['type']
            if kind in ('connected', 'snapshot'):
                for dev in ev.get('devices', []) if kind == 'snapshot' else [ev['device']]:
                    sid = uuid.uuid4().hex
                    session = {'id': sid, 'device': dev, 'created': ev['time'], 'wall': self.event_wall(ev),
                               'status': 'connected', 'baseline': kind == 'snapshot'}
                    self.active[sid] = session
                    self.store.save_session(session)
                    self.record(sid, 'usb', 'already_present' if kind == 'snapshot' else 'connected', dev,
                                attribution='device')
            elif kind == 'identity_changed':
                for sid, session in list(self.active.items()):
                    if session['status'] == 'connected' and session['device']['id'] == ev['device']['id']:
                        session['device'] = ev['device']
                        self.store.save_session(session)
                        self.record(sid, 'usb', 'identity_changed', ev, 'medium', 'device')
            else:
                for sid, session in list(self.active.items()):
                    if session['status'] == 'connected' and session['device']['id'] == ev['device']['id']:
                        session.update(status='disconnected', disconnected=time.time())
                        self.store.save_session(session)
                        self.record(sid, 'usb', 'removed', ev['device'], attribution='device')

    def tick(self):
        self.usb_events()
        capture = getattr(self.monitor, 'capture', None)
        if capture:
            for _ in range(4096):
                try: row = capture.messages.get_nowait()
                except queue.Empty: break
                category = row.get('category', 'native')
                if category == 'collector':
                    with self.lock: self.health['native'] = row['data']
                for sid in list(self.active):
                    if row.get('wall', time.time()) < self.active[sid]['wall']:
                        continue
                    attribution = 'temporal'
                    if category in ('hid', 'injection'):
                        dev = self.active[sid]['device']
                        data = row.get('data', {})
                        if category == 'injection': data = data.get('device', {})
                        try:
                            matched = (int(dev.get('location', ''), 16) == int(data['location_id']) and
                                       int(dev['vendor_id'], 16) == int(data['vendor_id']) and
                                       int(dev['product_id'], 16) == int(data['product_id']))
                        except (ValueError, TypeError, KeyError):
                            matched = False
                        if not matched:
                            continue
                        attribution = 'device'
                    self.record(sid, category, 'observed', row,
                                'medium' if category == 'injection' else 'info', attribution=attribution,
                                wall=row.get('wall'), precision='native_callback' if category != 'security' else 'log_received')
        for sid, s in list(self.active.items()):
            if s.get('disconnected') and time.time() - s['disconnected'] >= self.grace:
                self.record(sid, 'session', 'completed', {})
                s.update(status='completed', ended=now_iso())
                self.store.save_session(s)
                del self.active[sid]
        for category, fn in self.sources.items():
            complete = True
            started = time.time()
            try:
                current = fn()
                health = {'state': 'available', 'last_sample': now_iso()}
            except PartialSample as e:
                current, complete = e.data, False
                health = {'state': 'partial', 'error': str(e), 'last_sample': now_iso()}
            except Exception as e:
                with self.lock:
                    self.health[category] = {'state': 'unavailable', 'error': str(e), 'last_sample': now_iso()}
                continue
            health['duration_seconds'] = round(time.time() - started, 3)
            with self.lock: self.health[category] = health
            previous = self.previous.get(category)
            if previous is not None:
                for key, value in current.items():
                    if key not in previous or previous[key] != value:
                        action = 'created' if key not in previous else 'changed'
                        level = 'medium' if category == 'persistence' else 'info'
                        if category == 'process' and re.search(r'\b(curl|wget|osascript|bash|zsh|python|sudo)\b', value['command']):
                            level = 'medium'
                        for sid in list(self.active):
                            self.record(sid, category, action, {'key': key, 'after': value,
                                        'before': previous.get(key)}, level)
                if complete:
                    for key in previous.keys() - current.keys():
                        for sid in list(self.active):
                            self.record(sid, category, 'removed', {'key': key, 'before': previous[key]},
                                        'medium' if category == 'persistence' else 'info')
            self.previous[category] = current if complete else {**(previous or {}), **current}

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.tick()
                self.store.prune_telemetry()
            except Exception as e:
                with self.lock: self.health['engine'] = {'state': 'error', 'error': str(e)}
            self.stop_event.wait(self.interval)
