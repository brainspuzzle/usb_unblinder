const $ = (id) => document.getElementById(id);
const LEVELS = ['info', 'low', 'medium', 'high'];
const CLASS_NAMES = {
  0x00: 'Per-interface', 0x01: 'Audio', 0x02: 'Communications (CDC)', 0x03: 'HID', 0x05: 'Physical',
  0x06: 'Image', 0x07: 'Printer', 0x08: 'Mass storage', 0x09: 'Hub', 0x0A: 'CDC data', 0x0B: 'Smart card',
  0x0D: 'Content security', 0x0E: 'Video', 0x0F: 'Healthcare', 0x10: 'Audio/Video', 0x11: 'Billboard',
  0x12: 'USB-C bridge', 0xDC: 'Diagnostic', 0xE0: 'Wireless', 0xEF: 'Miscellaneous',
  0xFE: 'Application specific', 0xFF: 'Vendor specific',
};
const KIND_ICON = [
  ['keyboard', 'keyboard'], ['storage', 'storage'], ['network', 'network'], ['mouse', 'mouse'],
  ['camera', 'camera'], ['audio', 'audio'], ['bluetooth', 'bluetooth'], ['serial', 'serial'],
  ['dfu', 'chip'], ['hub', 'hub'], ['hid', 'hid'], ['billboard', 'display'], ['video', 'display'],
];
const RISKY_KINDS = new Set(['keyboard', 'network', 'dfu']);
const THEMES = ['auto', 'light', 'dark'];
const TABS = ['devices', 'activity', 'incidents', 'known'];

const state = {
  devices: {}, events: [], known: [], knownLoaded: false,
  tab: 'devices', level: 'info', query: '',
  drawerId: null, drawerDev: null, probes: {},
  incidents: [], incidentId: null, incidentTimer: null,
  fresh: new Map(), notify: false, theme: 'auto', lastBannerDev: null,
};

// ── helpers ───────────────────────────────────────────────────────────
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const icon = (name, cls = '') => `<svg class="icon ${cls}"><use href="#i-${name}"/></svg>`;
const hex = (n) => (n == null ? '?' : '0x' + Number(n).toString(16).padStart(2, '0'));
const bare = (id) => String(id || '?').replace(/^0x/i, '');
const vidpid = (d) => `${bare(d.vendor_id)}:${bare(d.product_id)}`;
const lvl = (l) => LEVELS.indexOf(l || 'info');
const store = {
  get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage blocked */ } },
};

function deviceIcon(kinds) {
  const set = new Set(kinds || []);
  const hit = KIND_ICON.find(([k]) => set.has(k));
  return hit ? hit[1] : 'usb';
}
function worst(findings) {
  return [...(findings || [])].sort((a, b) => lvl(b.level) - lvl(a.level))[0];
}
function notable(findings) {
  return (findings || []).filter((f) => f.level !== 'info');
}
function toDate(iso) { return iso ? new Date(iso) : null; }
function rel(iso) {
  const d = toDate(iso);
  if (!d) return '';
  const s = Math.round((Date.now() - d) / 1000);
  if (s < 10) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  const days = Math.floor(s / 86400);
  return days === 1 ? 'yesterday' : `${days} days ago`;
}
function clock(iso) { return iso ? iso.split('T')[1].slice(0, 8) : ''; }
function dayLabel(iso) {
  const d = toDate(iso);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const that = new Date(d); that.setHours(0, 0, 0, 0);
  const diff = Math.round((today - that) / 86400000);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  return d.toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' });
}
function kindChips(kinds) {
  return (kinds || []).map((k) => `<span class="chip ${RISKY_KINDS.has(k) ? 'warn' : ''}">${esc(k)}</span>`).join('');
}
function matches(obj) {
  if (!state.query) return true;
  const hay = [obj.name, obj.manufacturer, obj.vendor_id, obj.product_id, vidpid(obj), obj.serial,
    obj.location, (obj.kinds || []).join(' '), obj.fingerprint].join(' ').toLowerCase();
  return state.query.split(/\s+/).every((t) => hay.includes(t));
}
async function api(url, opts) {
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
const postJSON = (url, body) =>
  api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

// ── status / system info ──────────────────────────────────────────────
function setLive(mode, text) {
  $('live-pill').className = 'live-pill ' + mode;
  $('status-label').textContent = text;
}
async function loadStatus() {
  try {
    const s = await api('/api/status');
    const c = s.capabilities;
    const items = [
      [s.os, ''], [s.backend, ''], [`polling every ${s.poll_interval}s`, ''],
      [c.notifications ? 'desktop alerts on' : 'desktop alerts off', c.notifications ? 'ok' : 'off'],
      [c.screen_lock ? 'screen-lock detection' : 'no screen-lock detection', c.screen_lock ? 'ok' : 'off'],
      [c.probe.ok ? 'libusb probe ready' : `probe: ${c.probe.message}`, c.probe.ok ? 'ok' : 'off'],
    ];
    if (c.logs) { items.push([`logs: ${c.logs}`, '']); $('logs-path').textContent = c.logs; }
    $('sysinfo').innerHTML = items.map(([t, cls]) =>
      `<span class="${cls}">${cls ? '<span class="dot" style="--lvl: currentColor"></span>' : ''}${esc(t)}</span>`).join('');
    if (s.status.error) setLive('error', 'Backend error');
  } catch (e) { /* offline - stream handler shows it */ }
}

// ── devices ───────────────────────────────────────────────────────────
async function loadDevices() {
  const list = await api('/api/devices');
  state.devices = {};
  for (const d of list) state.devices[d.id] = d;
  renderDevices();
}
function renderDevices() {
  const all = Object.values(state.devices);
  const list = all.filter(matches)
    .sort((a, b) => lvl(b.level) - lvl(a.level) || a.name.localeCompare(b.name));
  $('count-devices').textContent = all.length;
  $('stat-devices').textContent = all.length;
  const kb = all.filter((d) => (d.kinds || []).includes('keyboard')).length;
  const st = all.filter((d) => (d.kinds || []).includes('storage')).length;
  $('hint-devices').textContent = `${kb} keyboard${kb === 1 ? '' : 's'} · ${st} storage`;

  $('devices-empty').hidden = list.length > 0;
  $('devices-empty-hint').textContent = all.length ? `Nothing matches “${state.query}”.` : 'Nothing is plugged in right now.';
  $('device-grid').innerHTML = list.map((d) => {
    const top = worst(notable(d.findings));
    const fresh = state.fresh.has(d.id) ? 'fresh' : '';
    return `
    <button class="card ${esc(d.level)} ${fresh}" data-id="${esc(d.id)}">
      <div class="card-top">
        <span class="dev-icon ${lvl(d.level) >= 1 && !d.trusted ? esc(d.level) : ''}">${icon(deviceIcon(d.kinds))}</span>
        <div class="card-title">
          <strong>${esc(d.name)}</strong>
          <div class="card-sub">${esc(d.manufacturer || 'Unknown vendor')} · <span class="mono">${esc(vidpid(d))}</span></div>
        </div>
        ${d.trusted ? `<span class="trusted-tag" title="Trusted">${icon('check')}</span>`
          : (lvl(d.level) >= 2 ? `<span class="badge ${esc(d.level)}">${esc(d.level)}</span>` : '')}
      </div>
      ${top ? `<div class="card-finding ${esc(top.level)}"><span class="dot"></span>${esc(top.message)}</div>` : ''}
      ${(d.kinds || []).length ? `<div class="chips">${kindChips(d.kinds)}</div>` : ''}
      <div class="card-foot">
        ${scanningFor(d.fingerprint) ? `<span class="card-scan"><span class="spinner"></span>Deep scan ${esc(scanningFor(d.fingerprint).progress.pass)}/${esc(scanningFor(d.fingerprint).progress.of)}</span>`
          : `<span class="meta">${esc(d.speed || 'speed unknown')}</span>`}
        <span class="mono">${esc(d.location)}</span>
      </div>
    </button>`;
  }).join('');
}
function refreshDrawer(fingerprint) {
  const d = state.drawerDev;
  if (!state.drawerId || !d || d.fingerprint !== fingerprint) return;
  renderDrawer(state.devices[state.drawerId] || d);
}
$('device-grid').addEventListener('click', (e) => {
  const card = e.target.closest('.card');
  if (card) openDrawer(state.devices[card.dataset.id]);
});

// ── activity ──────────────────────────────────────────────────────────
async function loadHistory() {
  state.events = (await api('/api/history?limit=2000')).filter((e) => e.type === 'connected' || e.type === 'removed');
  renderActivity();
}
function renderActivity() {
  const ev = state.events;
  $('count-activity').textContent = ev.length;
  $('stat-events').textContent = ev.length;
  $('hint-events').textContent = ev.length ? `last ${rel(ev[0].time)}` : 'nothing yet';
  const med = ev.filter((e) => e.level === 'medium').length;
  const high = ev.filter((e) => e.level === 'high').length;
  $('stat-medium').textContent = med;
  $('stat-high').textContent = high;
  $('hint-high').textContent = high ? `last ${rel(ev.find((e) => e.level === 'high').time)}` : 'all clear';
  $('hint-high').classList.toggle('good', !high);

  const shown = ev.filter((e) => lvl(e.level) >= lvl(state.level) && matches(e.device)).slice(0, 400);
  $('activity-empty').hidden = shown.length > 0;
  const days = [];
  for (const e of shown) {
    const label = dayLabel(e.time);
    if (!days.length || days[days.length - 1].label !== label) days.push({ label, items: [] });
    days[days.length - 1].items.push(e);
  }
  $('timeline').innerHTML = days.map((day) => `
    <div class="day">
      <div class="day-label">${esc(day.label)}</div>
      <div class="tl">${day.items.map(timelineItem).join('')}</div>
    </div>`).join('');
}
function timelineItem(e) {
  const d = e.device;
  const alarm = lvl(e.level) >= 2 ? esc(e.level) : '';
  const shown = notable(e.findings);
  const quiet = shown.length ? '' : (e.findings || []).map((f) => f.message).join(' · ');
  const fresh = state.fresh.has('ev:' + e.time + d.id) ? 'fresh' : '';
  return `
    <div class="tl-item ${fresh}" data-id="${esc(d.id)}">
      <span class="tl-icon ${esc(e.type)} ${alarm}">${icon(e.type === 'connected' ? 'plug' : 'unplug')}</span>
      <div class="tl-main">
        <div class="tl-head">
          <strong>${esc(d.name)}</strong>
          <span class="tl-verb">${e.type === 'connected' ? 'connected' : 'removed'}</span>
          ${lvl(e.level) >= 1 ? `<span class="badge ${esc(e.level)}">${esc(e.level)}</span>` : ''}
          ${d.trusted ? `<span class="trusted-tag">${icon('check')}trusted</span>` : ''}
        </div>
        <div class="tl-sub"><span class="mono">${esc(vidpid(d))}</span> · ${esc(d.manufacturer || 'Unknown vendor')}${(d.kinds || []).length ? ' · ' + esc(d.kinds.join(', ')) : ''}${quiet ? ' · ' + esc(quiet) : ''}</div>
        ${shown.length ? `<ul class="tl-findings">${shown.map((f) =>
          `<li class="${esc(f.level)}"><span class="dot"></span>${esc(f.message)}</li>`).join('')}</ul>` : ''}
      </div>
      <div class="tl-time"><span class="mono">${esc(clock(e.time))}</span>${esc(rel(e.time))}</div>
    </div>`;
}
$('timeline').addEventListener('click', (e) => {
  const item = e.target.closest('.tl-item');
  if (!item) return;
  const live = state.devices[item.dataset.id];
  const ev = state.events.find((x) => x.device.id === item.dataset.id);
  openDrawer(live || (ev && ev.device));
});
$('level-filter').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b) return;
  state.level = b.dataset.level;
  $('level-filter').querySelectorAll('button').forEach((x) => x.classList.toggle('active', x === b));
  renderActivity();
});

// ── known devices ─────────────────────────────────────────────────────
async function loadKnown() {
  state.known = await api('/api/known');
  state.knownLoaded = true;
  renderKnown();
}
function renderKnown() {
  $('count-known').textContent = state.known.length;
  const rows = state.known.filter(matches);
  $('known-empty').hidden = rows.length > 0 || !state.known.length;
  $('known-rows').innerHTML = rows.map((k) => `
    <tr>
      <td><div class="cell-dev"><span class="dev-icon">${icon(deviceIcon(k.kinds))}</span><strong>${esc(k.name)}</strong></div></td>
      <td class="mono">${esc(vidpid(k))}</td>
      <td class="mono muted">${esc(k.serial || '-')}</td>
      <td><div class="chips">${kindChips(k.kinds)}</div></td>
      <td class="muted" title="${esc(k.first_seen)}">${esc(rel(k.first_seen))}</td>
      <td class="muted" title="${esc(k.last_seen)}">${esc(rel(k.last_seen))}</td>
      <td class="num">${esc(k.seen_count)}</td>
      <td><label class="switch" title="Trusted"><input type="checkbox" data-fp="${esc(k.fingerprint)}" ${k.trusted ? 'checked' : ''}><span></span></label></td>
    </tr>`).join('');
}
$('known-rows').addEventListener('change', (e) => {
  if (e.target.dataset.fp) setTrusted(e.target.dataset.fp, e.target.checked);
});
async function setTrusted(fp, trusted) {
  try { await postJSON('/api/trust', { fingerprint: fp, trusted }); }
  catch (e) { toast({ level: 'high', title: 'Could not update trust', body: e.message, iconName: 'alert' }); }
}

// ── drawer ────────────────────────────────────────────────────────────
function itfLabel(i) {
  if (i.class === 3 && i.subclass === 1) return i.protocol === 1 ? 'HID · Keyboard (boot)' : i.protocol === 2 ? 'HID · Mouse (boot)' : 'HID (boot)';
  return CLASS_NAMES[i.class] || 'Class ' + hex(i.class);
}
function copyBtn(value) {
  return value ? `<button class="copy" data-copy="${esc(value)}" title="Copy">${icon('copy')}</button>` : '';
}
function openDrawer(d) {
  if (!d) return;
  state.incidentId = null;
  state.drawerId = d.id;
  state.drawerDev = d;
  renderDrawer(d);
  $('drawer').classList.add('open');
  $('backdrop').classList.add('open');
  $('drawer').setAttribute('aria-hidden', 'false');
}
function closeDrawer() {
  state.drawerId = null;
  state.incidentId = null;
  $('drawer').classList.remove('open');
  $('backdrop').classList.remove('open');
  $('drawer').setAttribute('aria-hidden', 'true');
}
function renderDrawer(d) {
  state.drawerDev = d;
  const live = !!state.devices[d.id];
  const alarm = lvl(d.level) >= 2 && !d.trusted;
  $('drawer-head').innerHTML = `
    <span class="dev-icon ${lvl(d.level) >= 1 && !d.trusted ? esc(d.level) : ''}">${icon(deviceIcon(d.kinds))}</span>
    <div class="grow">
      <h2>${esc(d.name)}</h2>
      <div class="card-sub">${esc(d.manufacturer || 'Unknown vendor')} · <span class="mono">${esc(vidpid(d))}</span>${live ? '' : ' · disconnected'}</div>
    </div>
    <button class="btn-icon ghost" id="drawer-close" title="Close (Esc)">${icon('x')}</button>`;

  const findings = [...(d.findings || [])].sort((a, b) => lvl(b.level) - lvl(a.level));
  const history = state.events.filter((e) => e.device.fingerprint === d.fingerprint).slice(0, 8);
  const itfs = d.interfaces || [];
  const probe = state.probes[d.id];

  $('drawer-body').innerHTML = `
    <section class="box ${alarm ? 'alarm ' + esc(d.level) : ''}">
      <h3>Assessment</h3>
      <div class="assess">
        <span class="badge ${esc(d.level)}">${esc(d.level || 'info')}</span>
        ${d.trusted ? `<span class="trusted-tag">${icon('check')}Trusted device</span>` : ''}
      </div>
      <ul class="findings">${findings.map((f) =>
        `<li class="${esc(f.level)}"><span class="dot"></span><span>${esc(f.message)}</span><span class="code mono">${esc(f.code)}</span></li>`).join('')
        || '<li class="muted">No findings</li>'}</ul>
    </section>

    <div class="actions">
      ${live ? `<button class="btn primary" id="drawer-deep" ${scanningFor(d.fingerprint) ? 'disabled' : ''}>${scanningFor(d.fingerprint) ? '<span class="spinner"></span>Deep scan running' : icon('activity') + 'Deep scan (60s)'}</button>` : ''}
      ${latestIncident(d.fingerprint) ? `<button class="btn" id="drawer-incident">${icon('alert')}View incident</button>` : ''}
      ${d.fingerprint ? `<button class="btn" id="drawer-trust">${icon(d.trusted ? 'x' : 'shield-check')}${d.trusted ? 'Remove trust' : 'Trust'}</button>` : ''}
      <button class="btn" id="drawer-probe">${icon('scan')}Probe descriptors</button>
    </div>
    ${probe ? `<section class="box"><h3>libusb probe</h3><pre>${esc(probe)}</pre></section>` : ''}

    <section class="box">
      <h3>Identity</h3>
      <dl class="props">
        <dt>VID:PID</dt><dd><span class="mono">${esc(vidpid(d))}</span>${copyBtn(vidpid(d))}</dd>
        <dt>Manufacturer</dt><dd>${esc(d.manufacturer || '-')}</dd>
        <dt>Serial</dt><dd><span class="mono">${esc(d.serial || '-')}</span>${copyBtn(d.serial)}</dd>
        <dt>Type</dt><dd><div class="chips">${kindChips(d.kinds) || '-'}</div></dd>
        <dt>Speed</dt><dd>${esc(d.speed || '-')}</dd>
        <dt>Location</dt><dd><span class="mono">${esc(d.location)}</span></dd>
        <dt>Fingerprint</dt><dd><span class="mono">${esc(d.fingerprint || '-')}</span>${copyBtn(d.fingerprint)}</dd>
      </dl>
    </section>

    <section class="box">
      <h3>Interfaces (${itfs.length})</h3>
      ${itfs.length ? itfs.map((i) => `
        <div class="itf"><span class="n">${esc(i.number ?? '?')}</span><span>${esc(itfLabel(i))}</span>
        <span class="mono">${hex(i.class)}/${hex(i.subclass)}/${hex(i.protocol)}</span></div>`).join('')
        : '<span class="muted">None reported by the OS</span>'}
    </section>

    ${history.length ? `
    <section class="box">
      <h3>Recent activity</h3>
      <div class="mini-tl">${history.map((e) => `
        <div class="${esc(e.level)}"><span class="mono">${esc(e.time.replace('T', ' ').slice(0, 19))}</span>
        <span class="dot"></span>${e.type === 'connected' ? 'Connected' : 'Removed'}</div>`).join('')}</div>
    </section>` : ''}

    <section class="box">
      <details><summary>Raw OS properties</summary><pre>${esc(JSON.stringify(d.raw, null, 2))}</pre></details>
    </section>`;

  $('drawer-close').onclick = closeDrawer;
  const trust = $('drawer-trust');
  if (trust) trust.onclick = () => setTrusted(d.fingerprint, !d.trusted);
  const deep = $('drawer-deep');
  if (deep) deep.onclick = async () => {
    try { openIncident((await postJSON('/api/scan', { device_id: d.id })).incident); }
    catch (err) { toast({ level: 'high', title: 'Could not start scan', body: err.message, iconName: 'alert' }); }
  };
  const incBtn = $('drawer-incident');
  if (incBtn) incBtn.onclick = () => openIncident(latestIncident(d.fingerprint).id);
  $('drawer-probe').onclick = async () => {
    state.probes[d.id] = 'Probing…';
    renderDrawer(d);
    try {
      state.probes[d.id] = JSON.stringify(await postJSON('/api/probe', { vid: d.vendor_id, pid: d.product_id }), null, 2);
    } catch (err) { state.probes[d.id] = 'Error: ' + err.message; }
    if (state.drawerId === d.id) renderDrawer(state.devices[d.id] || d);
  };
}
$('drawer').addEventListener('click', async (e) => {
  const b = e.target.closest('.copy');
  if (!b) return;
  try {
    await navigator.clipboard.writeText(b.dataset.copy);
    b.classList.add('done');
    b.innerHTML = icon('check');
    setTimeout(() => { b.classList.remove('done'); b.innerHTML = icon('copy'); }, 1200);
  } catch (err) { /* clipboard blocked */ }
});
$('backdrop').onclick = closeDrawer;

// ── incidents ─────────────────────────────────────────────────────────
function scanningFor(fp) { return state.incidents.find((i) => i.status === 'scanning' && i.fingerprint === fp); }
function latestIncident(fp) { return state.incidents.find((i) => i.fingerprint === fp); }
function statusChip(i) {
  if (i.status === 'scanning') return `<span class="status-chip scanning"><span class="spinner"></span>Scanning ${esc(i.progress.pass)}/${esc(i.progress.of)}</span>`;
  const label = { done: 'Scan complete', error: 'Scan failed', interrupted: 'Interrupted' }[i.status] || i.status;
  return `<span class="status-chip ${esc(i.status)}">${esc(label)}</span>`;
}
function progressBar(p) {
  return `<div class="progress"><span style="width:${Math.round(100 * p.pass / Math.max(p.of, 1))}%"></span></div>`;
}
async function loadIncidents() {
  state.incidents = await api('/api/incidents');
  renderIncidents();
}
function upsertIncident(s) {
  const i = state.incidents.findIndex((x) => x.id === s.id);
  if (i >= 0) state.incidents[i] = s; else state.incidents.unshift(s);
}
function renderIncidents() {
  const all = state.incidents;
  $('count-incidents').textContent = all.length;
  $('scan-dot').hidden = !all.some((i) => i.status === 'scanning');
  const list = all.filter((i) => matches({ ...i, serial: '', location: i.id }) ||
    (state.query && (i.summary || '').toLowerCase().includes(state.query)));
  $('incidents-empty').hidden = list.length > 0;
  $('incident-list').className = 'inc-list';
  $('incident-list').innerHTML = list.map((i) => {
    const shown = notable(i.findings).sort((a, b) => lvl(b.level) - lvl(a.level)).slice(0, 4);
    const done = i.status !== 'scanning' && i.report_path;
    return `
    <div class="inc ${esc(i.level)}" data-id="${esc(i.id)}">
      <span class="tl-icon ${lvl(i.level) >= 2 ? esc(i.level) : 'removed'}">${icon(lvl(i.level) >= 2 ? 'alert' : 'shield-check')}</span>
      <div class="tl-main">
        <div class="tl-head">
          <strong>${esc(i.name)}</strong>
          <span class="mono muted">${esc(vidpid(i))}</span>
          <span class="badge ${esc(i.level)}">${esc(i.level)}</span>
          ${statusChip(i)}
        </div>
        <div class="tl-sub">${esc(fmtWhen(i.created))} · ${i.reason === 'manual' ? 'manual scan' : 'automatic'} · <span class="mono">${esc(i.id)}</span>${i.related ? ` · +${esc(i.related)} related event(s)` : ''}</div>
        ${i.status === 'scanning' ? progressBar(i.progress) : ''}
        ${shown.length ? `<ul class="tl-findings">${shown.map((f) => `<li class="${esc(f.level)}"><span class="dot"></span>${esc(f.message)}</li>`).join('')}</ul>` : ''}
        <div class="inc-summary">${esc(i.summary)}</div>
      </div>
      <div class="inc-actions">
        ${done ? `<a class="btn" href="/api/incidents/${encodeURIComponent(i.id)}/report.txt" title="Readable report">${icon('download')}TXT</a>
        <a class="btn" href="/api/incidents/${encodeURIComponent(i.id)}/report.json" title="Full evidence">${icon('download')}JSON</a>` : ''}
      </div>
    </div>`;
  }).join('');
}
function fmtWhen(iso) { return `${iso.replace('T', ' ').slice(0, 19)} (${rel(iso)})`; }
$('incident-list').addEventListener('click', (e) => {
  if (e.target.closest('a')) return;
  const row = e.target.closest('.inc');
  if (row) openIncident(row.dataset.id);
});

async function openIncident(id) {
  state.drawerId = null;
  state.incidentId = id;
  $('drawer').classList.add('open');
  $('backdrop').classList.add('open');
  $('drawer').setAttribute('aria-hidden', 'false');
  const s = state.incidents.find((i) => i.id === id);
  $('drawer-head').innerHTML = incidentHead(s || { id, name: 'Incident', level: 'info' });
  $('drawer-close').onclick = closeDrawer;
  $('drawer-body').innerHTML = '<div class="muted-block"><span class="spinner"></span> Loading report…</div>';
  await fetchIncident();
}
async function fetchIncident() {
  const id = state.incidentId;
  if (!id) return;
  try {
    const r = await api('/api/incidents/' + encodeURIComponent(id));
    if (state.incidentId === id) renderIncident(r);
  } catch (e) {
    $('drawer-body').innerHTML = `<div class="muted-block">Could not load report: ${esc(e.message)}</div>`;
  }
}
function scheduleIncidentRefresh() {
  if (state.incidentTimer) return;
  state.incidentTimer = setTimeout(() => { state.incidentTimer = null; fetchIncident(); }, 700);
}
function incidentHead(r) {
  const d = r.device || r;
  return `
    <span class="dev-icon ${lvl(r.level) >= 1 ? esc(r.level) : ''}">${icon(lvl(r.level) >= 2 ? 'alert' : 'shield-check')}</span>
    <div class="grow">
      <h2>${esc(d.name)}</h2>
      <div class="card-sub">Incident <span class="mono">${esc(r.id)}</span></div>
    </div>
    <button class="btn-icon ghost" id="drawer-close" title="Close (Esc)">${icon('x')}</button>`;
}
function uniqueHid(r) {
  const seen = new Set();
  const out = [];
  for (const p of r.passes || []) {
    for (const h of (p.evidence || {}).hid || []) {
      if (!seen.has(h.descriptor_hex)) { seen.add(h.descriptor_hex); out.push(h); }
    }
  }
  return out;
}
function show(v) {
  if (v == null) return '-';
  if (Array.isArray(v)) return v.join(', ') || '-';
  if (typeof v === 'object') return v.error ? 'error: ' + v.error : Object.entries(v).map(([k, x]) => `${k} ${x}`).join(', ');
  return String(v);
}
function renderIncident(r) {
  $('drawer-head').innerHTML = incidentHead(r);
  $('drawer-close').onclick = closeDrawer;
  const d = r.device;
  const findings = [...(r.all_findings || [])].sort((a, b) => lvl(b.level) - lvl(a.level));
  const passes = r.passes || [];
  const ev0 = (passes.find((p) => p.evidence && !p.evidence.error) || {}).evidence || {};
  const base = r.baseline || {};
  const last = ([...passes].reverse().find((p) => p.context) || {}).context || {};
  const hids = uniqueHid(r);
  const procs = r.new_processes || [];
  const done = r.status !== 'scanning';

  const sections = [];
  sections.push(`
    <section class="box ${lvl(r.level) >= 2 ? 'alarm ' + esc(r.level) : ''}">
      <h3>Verdict</h3>
      <div class="assess"><span class="badge ${esc(r.level)}">${esc(r.level)}</span>${statusChip(r)}</div>
      ${r.status === 'scanning' ? progressBar(r.progress) : ''}
      <p class="inc-summary">${esc(r.summary)}</p>
      <ul class="findings">${findings.map((f) =>
        `<li class="${esc(f.level)}"><span class="dot"></span><span>${esc(f.message)}</span><span class="code mono">${esc(f.code)}</span></li>`).join('')}</ul>
    </section>
    <div class="actions">
      ${done && r.report_path ? `<a class="btn" href="/api/incidents/${encodeURIComponent(r.id)}/report.txt">${icon('download')}Report (TXT)</a>
      <a class="btn" href="/api/incidents/${encodeURIComponent(r.id)}/report.json">${icon('download')}Evidence (JSON)</a>` : ''}
      ${state.devices[Object.keys(state.devices).find((k) => state.devices[k].fingerprint === d.fingerprint)] && done
        ? `<button class="btn primary" id="inc-rescan">${icon('activity')}Re-scan now</button>` : ''}
    </div>`);

  sections.push(`
    <section class="box">
      <h3>Device</h3>
      <dl class="props">
        <dt>VID:PID</dt><dd><span class="mono">${esc(vidpid(d))}</span>${copyBtn(vidpid(d))}</dd>
        <dt>Manufacturer</dt><dd>${esc(d.manufacturer || '-')}</dd>
        <dt>Serial</dt><dd><span class="mono">${esc(d.serial || '-')}</span></dd>
        <dt>Type</dt><dd><div class="chips">${kindChips(d.kinds) || '-'}</div></dd>
        <dt>Location</dt><dd><span class="mono">${esc(d.location)}</span></dd>
        <dt>Trigger</dt><dd>${esc(r.reason === 'manual' ? 'manual scan' : `${r.trigger.type} event (${r.trigger.level})`)} · ${esc(fmtWhen(r.created))}</dd>
        ${(r.related_events || []).length ? `<dt>Related</dt><dd>${esc(r.related_events.length)} more event(s) during the scan</dd>` : ''}
      </dl>
    </section>`);

  sections.push(`
    <section class="box">
      <h3>Observation timeline</h3>
      <div class="sub">Device state at each pass after the trigger</div>
      <div class="passes">${passes.map((p) => {
        const e = p.evidence || {};
        const bits = [];
        if (e.drivers) bits.push(`${e.drivers.length} drivers`);
        if (e.hid && e.hid.length) bits.push(`${e.hid.length} HID`);
        if (e.disks && e.disks.length) bits.push(`${e.disks.length} disk`);
        if (e.network_interfaces && e.network_interfaces.length) bits.push('net ' + e.network_interfaces.map((i) => i.bsd).join(','));
        if (e.error) bits.push('error: ' + e.error);
        return `<div class="pass"><span class="mono">+${esc(p.offset)}s</span><span class="state ${esc(p.state)}">${esc(p.state)}</span>
          <span>${esc(bits.join(' · ') || '-')}${(p.changes || []).map((c) => `<span class="change">${esc(c.field)}: ${esc(show(c.before))} → ${esc(show(c.after))}</span>`).join('')}</span></div>`;
      }).join('') || '<span class="muted">Waiting for first pass…</span>'}</div>
    </section>`);

  if (hids.length) {
    sections.push(`
    <section class="box">
      <h3>HID capabilities</h3>
      ${hids.map((h) => {
        const c = h.decoded;
        const cap = (on, label, warn) => `<span class="cap ${on ? (warn ? 'warn' : 'on') : ''}">${on ? '' : 'no '}${label}</span>`;
        return `<div style="margin-bottom:12px">
          <strong>${esc(c.application_collections.join(', ') || 'No application collections')}</strong>
          <div class="cap-chips">${cap(c.can_type, 'typing', true)}${cap(c.can_point, 'pointing')}${cap(c.system_control, 'power keys', true)}${cap(c.consumer_control, 'media keys')}${cap(c.vendor_pages.length, 'vendor channel ' + c.vendor_pages.join(','), true)}</div>
          <div class="sub">${esc(c.inputs)} input / ${esc(c.outputs)} output / ${esc(c.features)} feature items · report IDs ${esc(show(c.report_ids))}</div>
          <details><summary>Report descriptor (${h.descriptor_hex.length / 2} bytes)</summary><pre>${esc(h.descriptor_hex.match(/.{1,2}/g).join(' '))}</pre></details>
        </div>`;
      }).join('')}
    </section>`);
  }

  if (r.input_activity) {
    const ia = r.input_activity;
    sections.push(`
    <section class="box">
      <h3>Input activity</h3>
      <div class="kv">
        <span class="k">Idle before</span><span>${esc(ia.idle_before_s)} s</span>
        <span class="k">First input</span><span class="${ia.first_input_after_connect_s != null ? 'changed' : ''}">${ia.first_input_after_connect_s != null ? esc(ia.first_input_after_connect_s) + ' s after connect' : 'none observed'}</span>
      </div>
    </section>`);
  }

  sections.push(`
    <section class="box">
      <h3>Processes started (${procs.length})</h3>
      <div class="sub">Processes that appeared after the trigger. Shell and scripting tools are highlighted.</div>
      ${procs.length ? [...procs].sort((a, b) => b.suspicious - a.suspicious || a.offset - b.offset).map((p) => `
        <div class="proc ${p.suspicious ? 'sus' : ''}"><span class="mono">${p.offset >= 0 ? '+' : ''}${esc(p.offset)}s</span>
          <div><strong>${esc(p.name)}</strong> <span class="muted mono">pid ${esc(p.pid)} ← ${esc(p.ppid)}</span>
          <div class="cmd" title="${esc(p.command)}">${esc(p.command)}</div></div></div>`).join('') : '<span class="muted">None</span>'}
    </section>`);

  const row = (k, a, b) => {
    const changed = JSON.stringify(a) !== JSON.stringify(b) && b !== undefined;
    return `<span class="k">${k}</span><span>${esc(show(a))}${changed ? `<br><span class="changed">→ ${esc(show(b))}</span>` : ''}</span>`;
  };
  sections.push(`
    <section class="box">
      <h3>System state: before → after</h3>
      <div class="kv">
        ${row('Interfaces', base.interfaces, last.interfaces)}
        ${row('Default route', base.default_route, last.default_route)}
        ${row('DNS', base.dns, last.dns)}
        ${row('Serial ports', base.serial_ports, last.serial_ports)}
      </div>
      ${(ev0.network_interfaces || []).map((i) => `<details><summary>Interface ${esc(i.bsd)}</summary><pre>${esc(i.ifconfig || '')}</pre></details>`).join('')}
    </section>`);

  for (const v of r.storage || []) {
    sections.push(`
    <section class="box ${(v.flagged || []).length ? 'alarm medium' : ''}">
      <h3>Volume ${esc(v.mountpoint)}</h3>
      <div class="sub">${esc(v.fstype || '')} · ${esc(v.entries || 0)} entries · ${esc(v.total_bytes || 0)} bytes${v.truncated ? ' · truncated' : ''}${v.error ? ' · ' + esc(v.error) : ''}</div>
      ${(v.flagged || []).map((f) => `<div class="file"><span class="mono">${esc(f.path)}</span><span class="why">${esc(f.reasons.join('; '))}</span></div>
        ${f.sha256 ? `<div class="sub mono">sha256 ${esc(f.sha256)}</div>` : ''}`).join('') || '<span class="muted">No flagged files</span>'}
      <details><summary>All files (${(v.tree || []).length})</summary><pre>${esc((v.tree || []).map((e) => `${e.dir ? 'd' : '-'} ${String(e.size ?? '').padStart(11)}  ${e.path}`).join('\n'))}</pre></details>
    </section>`);
  }

  if ((ev0.drivers || []).length || (ev0.open_by || []).length) {
    sections.push(`
    <section class="box">
      <h3>Drivers &amp; open handles</h3>
      ${(ev0.drivers || []).map((x) => `<div class="itf"><span class="n">${esc(x.depth ?? '')}</span><span>${esc(x.class)}</span><span class="mono">${esc(x.bundle)}</span></div>`).join('')}
      ${(ev0.open_by || []).length ? `<div class="sub" style="margin-top:10px">Opened by: ${esc([...new Set(ev0.open_by.map((o) => o.app))].join(', '))}</div>` : ''}
    </section>`);
  }

  if (r.probe) sections.push(`<section class="box"><details><summary>libusb descriptor probe</summary><pre>${esc(JSON.stringify(r.probe, null, 2))}</pre></details></section>`);
  if (r.system_log) {
    const lines = Array.isArray(r.system_log) ? r.system_log : [show(r.system_log)];
    sections.push(`<section class="box"><details><summary>System log (${lines.length} lines)</summary><pre>${esc(lines.join('\n'))}</pre></details></section>`);
  }
  if (r.error) sections.push(`<section class="box"><details open><summary>Scan error</summary><pre>${esc(r.error)}</pre></details></section>`);

  const openDetails = [...$('drawer-body').querySelectorAll('details')].map((x) => x.open);
  const scroll = $('drawer-body').scrollTop;
  $('drawer-body').innerHTML = sections.join('');
  $('drawer-body').querySelectorAll('details').forEach((x, i) => { if (openDetails[i]) x.open = true; });
  $('drawer-body').scrollTop = scroll;
  const rescan = $('inc-rescan');
  if (rescan) rescan.onclick = async () => {
    const dev = Object.values(state.devices).find((x) => x.fingerprint === d.fingerprint);
    try { openIncident((await postJSON('/api/scan', { device_id: dev.id })).incident); }
    catch (err) { toast({ level: 'high', title: 'Could not start scan', body: err.message, iconName: 'alert' }); }
  };
}

// ── alerts & toasts ───────────────────────────────────────────────────
function toast({ level = 'info', title, body, iconName, type, onClick }) {
  const el = document.createElement('div');
  el.className = `toast ${level}`;
  el.innerHTML = `
    <span class="tl-icon ${type || ''} ${lvl(level) >= 2 ? level : ''}">${icon(iconName || 'usb')}</span>
    <div class="toast-text"><strong>${esc(title)}</strong>${body ? `<span>${esc(body)}</span>` : ''}</div>`;
  const remove = () => { el.classList.add('gone'); setTimeout(() => el.remove(), 220); };
  el.onclick = () => { if (onClick) onClick(); remove(); };
  $('toasts').prepend(el);
  while ($('toasts').children.length > 4) $('toasts').lastChild.remove();
  setTimeout(remove, lvl(level) >= 2 ? 9000 : 5000);
}
function announce(ev) {
  const d = ev.device;
  const top = worst(notable(ev.findings));
  toast({
    level: ev.level, type: ev.type,
    iconName: ev.type === 'connected' ? 'plug' : 'unplug',
    title: `${ev.type === 'connected' ? 'Connected' : 'Removed'}: ${d.name}`,
    body: top ? top.message : `${vidpid(d)}${(d.kinds || []).length ? ' · ' + d.kinds.join(', ') : ''}`,
    onClick: () => openDrawer(state.devices[d.id] || d),
  });
  if (ev.type !== 'connected' || lvl(ev.level) < 2 || d.trusted) return;
  state.lastBannerDev = d;
  $('alert-banner').className = 'banner ' + ev.level;
  $('alert-title').textContent = `${ev.level === 'high' ? 'High risk' : 'Warning'}: ${d.name} (${vidpid(d)})`;
  $('alert-body').textContent = notable(ev.findings).map((f) => f.message).join(' · ');
  $('alert-banner').hidden = false;
  if (state.notify && document.hidden && 'Notification' in window && Notification.permission === 'granted') {
    new Notification(`USB ${ev.level}: ${d.name}`, { body: top ? top.message : vidpid(d) });
  }
}
$('alert-dismiss').onclick = () => { $('alert-banner').hidden = true; };
$('alert-view').onclick = () => {
  const d = state.lastBannerDev;
  if (d) openDrawer(state.devices[d.id] || d);
};

// ── preferences ───────────────────────────────────────────────────────
function applyTheme(t) {
  state.theme = t;
  if (t === 'auto') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
  $('theme-toggle').innerHTML = icon(t === 'auto' ? 'auto' : t === 'light' ? 'sun' : 'moon');
  $('theme-toggle').title = `Theme: ${t} (click to change)`;
  store.set('ub-theme', t);
}
$('theme-toggle').onclick = () => applyTheme(THEMES[(THEMES.indexOf(state.theme) + 1) % THEMES.length]);
applyTheme(THEMES.includes(store.get('ub-theme')) ? store.get('ub-theme') : 'auto');

function setNotify(on) {
  state.notify = on;
  const b = $('notify-toggle');
  b.innerHTML = icon(on ? 'bell' : 'bell-off');
  b.classList.toggle('on', on);
  b.title = on ? 'Browser notifications: on' : 'Browser notifications: off';
  store.set('ub-notify', on ? '1' : '0');
}
$('notify-toggle').onclick = async () => {
  if (!state.notify && 'Notification' in window && Notification.permission !== 'granted') {
    if (await Notification.requestPermission() !== 'granted') return;
  }
  setNotify(!state.notify);
};
setNotify(store.get('ub-notify') === '1');

// ── tabs, search, shortcuts ───────────────────────────────────────────
function showTab(tab) {
  state.tab = tab;
  document.querySelectorAll('[data-tab]').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  for (const t of TABS) $('tab-' + t).hidden = t !== tab;
  $('tools-activity').hidden = tab !== 'activity';
  if (tab === 'known') loadKnown().catch(() => {});
  store.set('ub-tab', tab);
}
document.querySelectorAll('[data-tab]').forEach((b) => { b.onclick = () => showTab(b.dataset.tab); });

$('search').addEventListener('input', (e) => {
  state.query = e.target.value.trim().toLowerCase();
  renderDevices(); renderActivity(); renderKnown(); renderIncidents();
});
document.addEventListener('keydown', (e) => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
  if (e.key === 'Escape') {
    if ($('drawer').classList.contains('open')) closeDrawer();
    else if (typing) { $('search').value = ''; $('search').dispatchEvent(new Event('input')); $('search').blur(); }
    return;
  }
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === '/') { e.preventDefault(); $('search').focus(); }
  else if (/^[1-4]$/.test(e.key)) showTab(TABS[Number(e.key) - 1]);
});

// ── live stream ───────────────────────────────────────────────────────
function markFresh(key) {
  state.fresh.set(key, Date.now());
  setTimeout(() => state.fresh.delete(key), 2500);
}
function handle(ev) {
  switch (ev.type) {
    case 'snapshot':
      state.devices = {};
      for (const d of ev.devices) state.devices[d.id] = d;
      renderDevices();
      break;
    case 'connected':
    case 'removed':
      if (ev.type === 'connected') { state.devices[ev.device.id] = ev.device; markFresh(ev.device.id); }
      else delete state.devices[ev.device.id];
      markFresh('ev:' + ev.time + ev.device.id);
      state.events.unshift(ev);
      renderDevices(); renderActivity();
      refreshDrawer(ev.device.fingerprint);
      if (state.knownLoaded) loadKnown().catch(() => {});
      announce(ev);
      break;
    case 'trust':
      for (const d of Object.values(state.devices)) if (d.fingerprint === ev.fingerprint) d.trusted = ev.trusted;
      if (state.drawerDev && state.drawerDev.fingerprint === ev.fingerprint) state.drawerDev.trusted = ev.trusted;
      renderDevices();
      refreshDrawer(ev.fingerprint);
      if (state.knownLoaded) loadKnown().catch(() => {});
      toast({ level: 'info', type: 'connected', iconName: ev.trusted ? 'shield-check' : 'x',
        title: ev.trusted ? 'Marked as trusted' : 'Trust removed' });
      break;
    case 'incident': {
      const i = ev.incident;
      const before = state.incidents.find((x) => x.id === i.id);
      upsertIncident(i);
      renderIncidents(); renderDevices();
      if (state.incidentId === i.id) scheduleIncidentRefresh();
      if (!before) {
        toast({ level: 'info', type: 'connected', iconName: 'activity', title: `Deep scan started: ${i.name}`,
          body: i.reason === 'manual' ? 'Manual scan · 8 passes over 60s' : 'Suspicious event · 8 passes over 60s', onClick: () => openIncident(i.id) });
      } else if (before.status === 'scanning' && i.status !== 'scanning') {
        toast({ level: i.level, type: 'connected', iconName: lvl(i.level) >= 2 ? 'alert' : 'shield-check',
          title: `Deep scan ${i.status === 'done' ? 'complete' : i.status}: ${i.name}`, body: i.summary, onClick: () => openIncident(i.id) });
        if (state.drawerId) refreshDrawer(i.fingerprint);
      }
      break;
    }
    case 'device_update':
      if (state.devices[ev.device.id]) {
        state.devices[ev.device.id] = ev.device;
        renderDevices();
        refreshDrawer(ev.device.fingerprint);
      }
      break;
    case 'status':
      if (ev.status.error) setLive('error', 'Backend error');
      else setLive('live', 'Live');
      break;
  }
}
function connect() {
  const es = new EventSource('/api/events');
  es.onopen = () => {
    setLive('live', 'Live');
    loadDevices().catch(() => {});
    loadStatus();
  };
  es.onerror = () => setLive('', 'Reconnecting');
  es.onmessage = (e) => handle(JSON.parse(e.data));
}

setInterval(() => { renderActivity(); renderIncidents(); if (state.tab === 'known') renderKnown(); }, 30000);
showTab(TABS.includes(store.get('ub-tab')) ? store.get('ub-tab') : 'devices');
loadHistory().catch(() => {});
loadKnown().catch(() => {});
loadIncidents().catch(() => {});
connect();
