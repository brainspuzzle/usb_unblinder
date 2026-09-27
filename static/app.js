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

const state = {
  devices: {}, events: [], known: [], knownLoaded: false,
  tab: 'devices', level: 'info', query: '',
  drawerId: null, drawerDev: null, probes: {},
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
        <span class="meta">${esc(d.speed || 'speed unknown')}</span>
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
  state.drawerId = d.id;
  state.drawerDev = d;
  renderDrawer(d);
  $('drawer').classList.add('open');
  $('backdrop').classList.add('open');
  $('drawer').setAttribute('aria-hidden', 'false');
}
function closeDrawer() {
  state.drawerId = null;
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
      ${d.fingerprint ? `<button class="btn ${d.trusted ? '' : 'primary'}" id="drawer-trust">${icon(d.trusted ? 'x' : 'shield-check')}${d.trusted ? 'Remove trust' : 'Trust this device'}</button>` : ''}
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
  for (const t of ['devices', 'activity', 'known']) $('tab-' + t).hidden = t !== tab;
  $('tools-activity').hidden = tab !== 'activity';
  if (tab === 'known') loadKnown().catch(() => {});
  store.set('ub-tab', tab);
}
document.querySelectorAll('[data-tab]').forEach((b) => { b.onclick = () => showTab(b.dataset.tab); });

$('search').addEventListener('input', (e) => {
  state.query = e.target.value.trim().toLowerCase();
  renderDevices(); renderActivity(); renderKnown();
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
  else if (e.key === '1') showTab('devices');
  else if (e.key === '2') showTab('activity');
  else if (e.key === '3') showTab('known');
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

setInterval(() => { renderActivity(); if (state.tab === 'known') renderKnown(); }, 30000);
showTab(['devices', 'activity', 'known'].includes(store.get('ub-tab')) ? store.get('ub-tab') : 'devices');
loadHistory().catch(() => {});
loadKnown().catch(() => {});
connect();
