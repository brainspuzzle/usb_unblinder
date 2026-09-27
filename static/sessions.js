(() => {
  const select = document.getElementById('session-select');
  const category = document.getElementById('session-category');
  let rows = [], cursor = 0, selected = '', busy = false, settingsLoaded = false;
  const el = (tag, text) => {const node = document.createElement(tag); node.textContent = text; return node;};
  function render() {
    const root = document.getElementById('session-timeline'); root.replaceChildren();
    for (const row of rows.filter(r => !category.value || r.category === category.value).slice(-1000).reverse()) {
      const detail = el('details', ''); detail.className = 'telemetry-row';
      detail.append(el('summary', `${row.time}  +${row.elapsed.toFixed(3)}s  [${row.level}] ${row.category} / ${row.action} · ${row.attribution}`));
      detail.append(el('pre', JSON.stringify(row.data, null, 2))); root.append(detail);
    }
    if (!root.children.length) root.append(el('p', 'No observations for this selection yet.'));
  }
  async function refresh() {
    if (busy || document.getElementById('tab-sessions').hidden) return;
    busy = true;
    try {
      const [sessions, health] = await Promise.all(['/api/sessions','/api/telemetry'].map(async u => {const r=await fetch(u); if(!r.ok) throw Error(r.status); return r.json();}));
      document.getElementById('telemetry-health').textContent = JSON.stringify(health, null, 2);
      if(!settingsLoaded) {
        document.getElementById('telemetry-interval').value=health.interval_seconds;
        document.getElementById('telemetry-grace').value=health.post_disconnect_seconds;
        document.getElementById('telemetry-roots').value=health.file_roots.join('\n'); settingsLoaded=true;
      }
      const wanted = select.value || sessions[0]?.id || '';
      select.replaceChildren(...sessions.map(s => {const o=el('option', `${s.device.name} · ${s.created} · ${s.status}`); o.value=s.id; return o;}));
      select.value = wanted;
      if (selected !== select.value) {selected=select.value; rows=[]; cursor=0;}
      if (selected) {
        const response = await fetch(`/api/sessions/${selected}/events?after=${cursor}`);
        if(!response.ok) throw Error(response.status);
        const incoming=await response.json(); rows.push(...incoming); rows=rows.slice(-5000);
        if(incoming.length) cursor=incoming[incoming.length-1].id;
        for (const fmt of ['json','txt']) document.getElementById('session-'+fmt).href=`/api/sessions/${selected}/export.${fmt}`;
      }
      await refreshCapture();
      render();
    } catch(e) {document.getElementById('telemetry-health').textContent = `Refresh failed: ${e.message}`;}
    finally {busy=false;}
  }
  async function refreshCapture() {
    const r=await fetch('/api/capture'); if(!r.ok) throw Error(r.status); const status=await r.json();
    document.getElementById('capture-status').textContent=JSON.stringify(status,null,2);
    const interfaces=document.getElementById('capture-interface'), wanted=interfaces.value;
    interfaces.replaceChildren(...status.interfaces.map(name => {const o=el('option', name);o.value=name;return o;}));
    if(status.interfaces.includes(wanted)) interfaces.value=wanted;
    const files=document.getElementById('capture-files'); files.replaceChildren();
    for(const f of status.files) {const a=el('a', `${f.name} (${f.size} bytes)`); a.href='/api/capture/files/'+encodeURIComponent(f.name);files.append(a, el('br',''));}
  }
  document.querySelectorAll('[data-capture]').forEach(button => button.onclick=async () => {
    button.disabled=true;
    try {
      const r=await fetch('/api/capture/'+button.dataset.capture,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({keys:document.getElementById('capture-keys').checked,interface:document.getElementById('capture-interface').value})});
      const result=await r.json(); if(!r.ok) throw Error(result.error); await refreshCapture();
    } catch(e) {document.getElementById('capture-status').textContent=e.message;}
    finally {button.disabled=false;}
  });
  document.getElementById('telemetry-save').onclick=async () => {
    try {
      const r=await fetch('/api/telemetry/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
        interval_seconds:Number(document.getElementById('telemetry-interval').value),
        post_disconnect_seconds:Number(document.getElementById('telemetry-grace').value),
        file_roots:document.getElementById('telemetry-roots').value.split('\n').map(x=>x.trim()).filter(Boolean)})});
      const result=await r.json(); if(!r.ok) throw Error(result.error);
      document.getElementById('telemetry-settings-result').textContent='Saved';
    } catch(e) {document.getElementById('telemetry-settings-result').textContent=e.message;}
  };
  select.onchange=refresh; category.onchange=render;
  document.getElementById('session-delete').onclick=async () => {
    if(!selected) return;
    const r=await fetch(`/api/sessions/${selected}/delete`,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    if(!r.ok) {alert((await r.json()).error);return;} select.value=''; selected=''; rows=[]; cursor=0; refresh();
  };
  document.querySelector('[data-tab="sessions"]').addEventListener('click', refresh);
  setInterval(refresh, 2000); refresh();
})();
