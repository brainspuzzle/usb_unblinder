const $ = (id) => document.getElementById(id);
const LEVELS = ['info', 'low', 'medium', 'high'];
const CLASS_NAMES = {
  0x00: 'per-interface', 0x01: 'Audio', 0x02: 'Communications (CDC)', 0x03: 'HID', 0x05: 'Physical',
  0x06: 'Image', 0x07: 'Printer', 0x08: 'Mass storage', 0x09: 'Hub', 0x0A: 'CDC data', 0x0B: 'Smart card',
  0x0D: 'Content security', 0x0E: 'Video', 0x0F: 'Healthcare', 0x10: 'Audio/Video', 0x11: 'Billboard',
  0x12: 'USB-C bridge', 0xDC: 'Diagnostic', 0xE0: 'Wireless', 0xEF: 'Miscellaneous',
  0xFE: 'Application specific', 0xFF: 'Vendor specific',
};

const state = { devices: {}, events: [], known: [], filter: 'info', drawerId: null, notify: false };

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function hex(n, width = 2) { return n == null ? '?' : '0x' + Number(n).toString(16).padStart(width, '0'); }
function fmtTime(iso) {
  if (!iso) return '';
  const [date, time] = iso.split('T');
  const today = new Date().toLocaleDateString('sv');
  return (date === today ? '' : date + ' ') + time.slice(0, 8);
}
function lvlIndex(l) { return LEVELS.indexOf(l || 'info'); }
async function api(url, opts) {
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
function postJSON(url, body) {
  return api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}
function kindChips(kinds) { return (kinds || []).map((k) => `<span class="kind ${esc(k)}">${esc(k)}</span>`).join(''); }
function findingsList(findings) {
  if (!findings || !findings.length) return '';
  return '<ul class="findings">' + findings.map((f) =>
    `<li><span class="badge ${esc(f.level)}">${esc(f.level)}</span>${esc(f.message)}</li>`).join('') + '</ul>';
}

// ── status ────────────────────────────────────────────────────────────
async function loadStatus() {
  try {
    const s = await api('/api/status');
    const caps = s.capabilities;
    const chips = [
      [s.os, ''], [s.backend, ''], [`poll ${s.poll_interval}s`, ''],
      [caps.notifications ? `desktop alerts: ${caps.notifications}` : 'desktop alerts: off', caps.notifications ? 'ok' : 'off'],
      [caps.screen_lock ? 'lock detection' : 'no lock detection', caps.screen_lock ? 'ok' : 'off'],
      [caps.probe.ok ? 'probe: libusb ready' : `probe: ${caps.probe.message}`, caps.probe.ok ? 'ok' : 'off'],
    ];
    $('platform-chips').innerHTML = chips.map(([t, c]) => `<span class="chip ${c}">${esc(t)}</span>`).join('');
    applyStatus(s.status);
  } catch (e) { /* server down - SSE handler shows it */ }
}
function applyStatus(st) {
  if (st && st.error) {
    $('status-label').textContent = 'backend error: ' + st.error;
    $('status-dot').classList.remove('live');
  }
}

// ── devices ───────────────────────────────────────────────────────────
async function loadDevices() {
  const list = await api('/api/devices');
  state.devices = {};
  for (const d of list) state.devices[d.id] = d;
  renderDevices();
}
function renderDevices() {
  const list = Object.values(state.devices)
    .sort((a, b) => lvlIndex(b.level) - lvlIndex(a.level) || a.name.localeCompare(b.name));
  $('stat-devices').textContent = list.length;
  $('devices-empty').hidden = list.length > 0;
  $('device-rows').innerHTML = list.map((d) => `
    <tr data-id="${esc(d.id)}">
      <td><span class="lvl ${esc(d.level)}" title="${esc(d.level)}"></span></td>
      <td class="name">${esc(d.name)}${d.trusted ? '<span class="trusted">trusted</span>' : ''}<br>${kindChips(d.kinds)}</td>
      <td class="mono">${esc(d.vendor_id)}:${esc(d.product_id)}</td>
      <td>${esc(d.manufacturer || '-')}</td>
      <td class="mono">${esc(d.serial || '-')}</td>
      <td>${esc(d.speed || '-')}</td>
      <td class="mono">${esc(d.location)}</td>
    </tr>`).join('');
  if (state.drawerId && state.devices[state.drawerId]) openDrawer(state.devices[state.drawerId]);
}
$('device-rows').addEventListener('click', (e) => {
  const row = e.target.closest('tr');
  if (row) openDrawer(state.devices[row.dataset.id]);
});

// ── drawer ────────────────────────────────────────────────────────────
function openDrawer(d) {
  if (!d) return;
  state.drawerId = d.id;
  $('drawer-title').textContent = d.name;
  const itfs = (d.interfaces || []).map((i) =>
    `<tr><td>${esc(i.number)}</td><td>${esc(CLASS_NAMES[i.class] || hex(i.class))}</td><td class="mono">${hex(i.class)}/${hex(i.subclass)}/${hex(i.protocol)}</td></tr>`).join('');
  $('drawer-body').innerHTML = `
    <h3>Assessment</h3>
    <div><span class="badge ${esc(d.level)}">${esc(d.level)}</span> ${d.trusted ? '<span class="trusted">trusted</span>' : ''}</div>
    ${findingsList(d.findings)}
    <h3>Identity</h3>
    <dl class="props">
      <dt>VID:PID</dt><dd class="mono">${esc(d.vendor_id)}:${esc(d.product_id)}</dd>
      <dt>Manufacturer</dt><dd>${esc(d.manufacturer || '-')}</dd>
      <dt>Serial</dt><dd class="mono">${esc(d.serial || '-')}</dd>
      <dt>Type</dt><dd>${kindChips(d.kinds) || '-'}</dd>
      <dt>Speed</dt><dd>${esc(d.speed || '-')}</dd>
      <dt>Location</dt><dd class="mono">${esc(d.location)}</dd>
      <dt>Fingerprint</dt><dd class="mono">${esc(d.fingerprint)}</dd>
    </dl>
    <h3>Interfaces</h3>
    ${itfs ? `<table><thead><tr><th>#</th><th>Class</th><th>class/sub/proto</th></tr></thead><tbody>${itfs}</tbody></table>` : '<p class="muted">None reported</p>'}
    <div class="actions">
      <button id="drawer-trust">${d.trusted ? 'Remove trust' : 'Trust this device'}</button>
      <button class="ghost" id="drawer-probe">Probe descriptors (libusb)</button>
    </div>
    <pre id="drawer-probe-out" hidden></pre>
    <h3>Raw OS properties</h3>
    <pre>${esc(JSON.stringify(d.raw, null, 2))}</pre>`;
  $('drawer').hidden = false;
  $('drawer-trust').onclick = () => setTrusted(d.fingerprint, !d.trusted);
  $('drawer-probe').onclick = async () => {
    const out = $('drawer-probe-out');
    out.hidden = false;
    out.textContent = 'Probing…';
    try {
      const r = await postJSON('/api/probe', { vid: d.vendor_id, pid: d.product_id });
      out.textContent = JSON.stringify(r, null, 2);
    } catch (err) { out.textContent = 'Error: ' + err.message; }
  };
}
$('drawer-close').onclick = () => { $('drawer').hidden = true; state.drawerId = null; };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('drawer-close').click(); });

async function setTrusted(fp, trusted) {
  try { await postJSON('/api/trust', { fingerprint: fp, trusted }); }
  catch (e) { alert('Could not update trust: ' + e.message); }
}

// ── events ────────────────────────────────────────────────────────────
async function loadHistory() {
  state.events = await api('/api/history?limit=2000');
  renderEvents();
}
function renderEvents() {
  const plugs = state.events.filter((e) => e.type === 'connected' || e.type === 'removed');
  $('stat-events').textContent = plugs.length;
  $('stat-medium').textContent = plugs.filter((e) => e.level === 'medium').length;
  $('stat-high').textContent = plugs.filter((e) => e.level === 'high').length;
  const shown = plugs.filter((e) => lvlIndex(e.level) >= lvlIndex(state.filter)).slice(0, 500);
  $('events-empty').hidden = shown.length > 0;
  $('event-list').innerHTML = shown.map((e) => `
    <div class="event">
      <div class="event-head">
        <span class="muted mono">${esc(fmtTime(e.time))}</span>
        <span class="event-type ${esc(e.type)}">${e.type === 'connected' ? 'CONNECTED' : 'REMOVED'}</span>
        <span class="badge ${esc(e.level)}">${esc(e.level)}</span>
        <strong>${esc(e.device.name)}</strong>
        <span class="mono muted">${esc(e.device.vendor_id)}:${esc(e.device.product_id)}</span>
        ${kindChips(e.device.kinds)}
      </div>
      ${findingsList(e.findings.filter((f) => f.level !== 'info' || e.findings.length < 3))}
    </div>`).join('');
}
$('event-filter').onchange = (e) => { state.filter = e.target.value; renderEvents(); };

// ── known devices ─────────────────────────────────────────────────────
async function loadKnown() {
  state.known = await api('/api/known');
  $('known-rows').innerHTML = state.known.map((k) => `
    <tr>
      <td><input type="checkbox" data-fp="${esc(k.fingerprint)}" ${k.trusted ? 'checked' : ''}></td>
      <td>${esc(k.name)}</td>
      <td class="mono">${esc(k.vendor_id)}:${esc(k.product_id)}</td>
      <td class="mono">${esc(k.serial || '-')}</td>
      <td>${kindChips(k.kinds)}</td>
      <td>${esc(fmtTime(k.first_seen))}</td>
      <td>${esc(fmtTime(k.last_seen))}</td>
      <td>${esc(k.seen_count)}</td>
    </tr>`).join('');
}
$('known-rows').addEventListener('change', (e) => {
  if (e.target.dataset.fp) setTrusted(e.target.dataset.fp, e.target.checked);
});

// ── alerts ────────────────────────────────────────────────────────────
function alertFor(ev) {
  if (ev.type !== 'connected' || lvlIndex(ev.level) < 2 || ev.device.trusted) return;
  const worst = [...ev.findings].sort((a, b) => lvlIndex(b.level) - lvlIndex(a.level))[0];
  $('alert-banner').className = 'banner ' + ev.level;
  $('alert-title').textContent = `${ev.level.toUpperCase()}: ${ev.device.name} (${ev.device.vendor_id}:${ev.device.product_id})`;
  $('alert-body').textContent = ev.findings.filter((f) => f.level !== 'info').map((f) => f.message).join(' · ');
  $('alert-banner').hidden = false;
  if (state.notify && document.hidden && 'Notification' in window && Notification.permission === 'granted') {
    new Notification(`USB ${ev.level}: ${ev.device.name}`, { body: worst.message });
  }
}
$('alert-dismiss').onclick = () => { $('alert-banner').hidden = true; };

function setNotify(on) {
  state.notify = on;
  $('notify-toggle').textContent = 'Browser alerts: ' + (on ? 'on' : 'off');
  try { localStorage.setItem('ub-notify', on ? '1' : '0'); } catch (e) { /* storage blocked */ }
}
$('notify-toggle').onclick = async () => {
  if (!state.notify && 'Notification' in window && Notification.permission !== 'granted') {
    if (await Notification.requestPermission() !== 'granted') return;
  }
  setNotify(!state.notify);
};
try { if (localStorage.getItem('ub-notify') === '1') setNotify(true); } catch (e) { /* storage blocked */ }

// ── live stream ───────────────────────────────────────────────────────
function handle(ev) {
  switch (ev.type) {
    case 'snapshot':
      state.devices = {};
      for (const d of ev.devices) state.devices[d.id] = d;
      renderDevices();
      break;
    case 'connected':
      state.devices[ev.device.id] = ev.device;
      state.events.unshift(ev);
      renderDevices(); renderEvents(); alertFor(ev);
      break;
    case 'removed':
      delete state.devices[ev.device.id];
      state.events.unshift(ev);
      renderDevices(); renderEvents();
      break;
    case 'trust':
      for (const d of Object.values(state.devices)) if (d.fingerprint === ev.fingerprint) d.trusted = ev.trusted;
      renderDevices();
      if (!$('tab-known').hidden) loadKnown();
      break;
    case 'status':
      if (ev.status.error) applyStatus(ev.status);
      else { $('status-label').textContent = 'live'; $('status-dot').classList.add('live'); }
      break;
  }
}
function connect() {
  const es = new EventSource('/api/events');
  es.onopen = () => {
    $('status-dot').classList.add('live');
    $('status-label').textContent = 'live';
    loadDevices().catch(() => {});
    loadStatus();
  };
  es.onerror = () => {
    $('status-dot').classList.remove('live');
    $('status-label').textContent = 'reconnecting…';
  };
  es.onmessage = (e) => handle(JSON.parse(e.data));
}

// ── tabs ──────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach((btn) => {
  btn.onclick = () => {
    document.querySelectorAll('.tab').forEach((b) => b.classList.toggle('active', b === btn));
    document.querySelectorAll('.tab-panel').forEach((p) => { p.hidden = p.id !== 'tab-' + btn.dataset.tab; });
    if (btn.dataset.tab === 'known') loadKnown();
  };
});

loadHistory().catch(() => {});
connect();
