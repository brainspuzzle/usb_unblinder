import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from unblinder.store import Store
from unblinder.telemetry import Telemetry, PartialSample, Collectors
from app import create_app


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.store.init_telemetry()
        self.sent = []
        self.monitor = SimpleNamespace(store=self.store, emit=lambda e, **kw: self.sent.append(e))
        self.t = Telemetry(self.monitor, grace=0)
        self.monitor.telemetry = self.t
        self.t.sources = {}

    def tearDown(self):
        self.store.db.close()

    def connect(self):
        self.t.on_event({'type': 'connected', 'time': '2026-01-01T00:00:00Z',
                         'device': {'id': 'usb1', 'name': 'Test'}})
        self.t.tick()
        return self.store.sessions()[0]['id']

    def test_lifecycle_and_attribution(self):
        sid = self.connect()
        self.t.sources = {'process': lambda: {}}
        self.t.tick()
        self.t.sources = {'process': lambda: {'12:1': {'pid': 12, 'command': 'curl example.invalid'}}}
        self.t.tick()
        rows = self.store.observations(sid)
        self.assertEqual(rows[0]['attribution'], 'device')
        self.assertEqual(rows[-1]['attribution'], 'temporal')
        self.assertEqual(rows[-1]['level'], 'medium')
        self.t.on_event({'type': 'removed', 'device': {'id': 'usb1'}})
        self.t.tick()
        self.assertEqual(self.store.sessions()[0]['status'], 'completed')
        self.assertFalse(self.t.active)

    def test_partial_sample_does_not_invent_deletions(self):
        sid = self.connect()
        self.t.sources = {'file': lambda: {'a': 1}}
        self.t.tick()
        def partial(): raise PartialSample({}, ['denied'])
        self.t.sources = {'file': partial}
        self.t.tick()
        self.assertEqual(len(self.store.observations(sid)), 1)
        self.assertEqual(self.t.health['file']['state'], 'partial')
        self.assertIn('a', self.t.previous['file'])

    def test_error_preserves_baseline(self):
        sid=self.connect()
        self.t.previous['file']={'a':1}
        def fail(): raise PermissionError('denied')
        self.t.sources={'file':fail}
        self.t.tick()
        self.assertEqual(self.t.health['file']['state'],'unavailable')
        self.assertEqual(self.t.previous['file'],{'a':1})

    def test_restart_marks_interrupted(self):
        self.connect()
        self.store.init_telemetry()
        self.assertEqual(self.store.sessions()[0]['status'], 'interrupted')

    def test_api_pagination_export_delete(self):
        sid=self.connect()
        client=create_app(self.monitor,'127.0.0.1').test_client()
        self.assertEqual(client.get('/api/sessions').status_code,200)
        rows=client.get(f'/api/sessions/{sid}/events').json
        self.assertEqual(client.get(f'/api/sessions/{sid}/events?after={rows[-1]["id"]}').json,[])
        self.assertEqual(client.get(f'/api/sessions/{sid}/export.txt').status_code,200)
        self.assertEqual(client.post(f'/api/sessions/{sid}/delete',json={}).status_code,409)
        self.t.active.clear()
        self.assertEqual(client.post(f'/api/sessions/{sid}/delete',json={}).status_code,200)
        self.assertEqual(self.store.observations(sid),[])
        self.assertEqual(client.get('/api/sessions',headers={'Host':'evil.example'}).status_code,403)

    def test_file_changes_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'file').write_text('one'); (root/'link').symlink_to('/etc')
            c=Collectors(); c.roots=[root]
            before=c.files(); self.assertEqual(len(before),1)
            (root/'file').write_text('longer'); self.assertNotEqual(before,c.files())

    def test_native_hid_requires_matching_device(self):
        import queue
        import time
        sid=self.connect()
        self.t.active[sid]['device'].update(location='0x01000000',vendor_id='1234',product_id='5678')
        messages=queue.Queue()
        self.monitor.capture=SimpleNamespace(messages=messages)
        for location in (16777216, 999):
            messages.put({'category':'hid','wall':time.time(),'data':{
                'location_id':location,'vendor_id':4660,'product_id':22136,'page':7,'pressed':True}})
        self.t.tick()
        rows=[r for r in self.store.observations(sid) if r['category']=='hid']
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['attribution'],'device')
        self.assertEqual(rows[0]['precision'],'native_callback')

    def test_settings_validation(self):
        client=create_app(self.monitor,'127.0.0.1').test_client()
        self.assertEqual(client.post('/api/telemetry/settings',json={'interval_seconds':-1}).status_code,400)
        self.assertEqual(client.post('/api/telemetry/settings',json={'file_roots':['relative']}).status_code,400)
        with tempfile.TemporaryDirectory() as directory:
            response=client.post('/api/telemetry/settings',json={'file_roots':[directory], 'post_disconnect_seconds':5})
            self.assertEqual(response.status_code,200)
            self.assertEqual(self.t.grace,5)

    def test_identity_changes_are_device_evidence(self):
        sid=self.connect()
        self.t.on_event({'type':'identity_changed','device':{'id':'usb1','name':'Changed'}})
        self.t.tick()
        rows=self.store.observations(sid)
        self.assertEqual(rows[-1]['action'],'identity_changed')
        self.assertEqual(rows[-1]['attribution'],'device')

    def test_capture_refuses_unknown_interface(self):
        from unblinder.capture import Capture
        with tempfile.TemporaryDirectory() as directory:
            capture=Capture(directory)
            with patch.object(capture, 'interfaces', return_value=['en0']):
                with self.assertRaises(ValueError): capture.start('packets', 'en0; touch /tmp/unsafe')
            self.assertEqual(capture.status()['jobs'],{})

if __name__=='__main__': unittest.main()
