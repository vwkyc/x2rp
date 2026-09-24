// x2rp admin console.

const pick = selector => document.querySelector(selector);
const pickAll = selector => document.querySelectorAll(selector);

const state = {
  connectors: [],
  routes: [],
  connectorId: null, // connector open in the detail dialog
  routeId: null,  // route open in the editor; null while creating
};

// Values are interpolated into HTML text and attributes, so quotes are escaped too.
const HTML_ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const html = value => String(value ?? '').replace(/[&<>"']/g, ch => HTML_ENTITIES[ch]);

const splitList = text => String(text || '').split(',').map(item => item.trim()).filter(Boolean);

function csrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)__Host-x2rp_csrf=([^;]*)/);
  return match ? match[1] : null;
}

async function request(method, path, payload) {
  const headers = {};
  if (payload) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') {
    const token = csrfToken();
    if (token) headers['X-CSRF-Token'] = token;
  }
  const response = await fetch('/api' + path, {
    method,
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
    body: payload ? JSON.stringify(payload) : undefined,
  });
  if (response.status === 204) return null;
  const text = await response.text();
  if (!response.ok) {
    const error = new Error(`${response.status} ${text || response.statusText}`.trim());
    error.status = response.status;
    throw error;
  }
  if (!text) return null;
  try { return JSON.parse(text); } catch { return text; }
}

function timeAgo(iso) {
  if (!iso) return 'Never';
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return 'Just now';
  for (const [size, unit] of [[86400, 'day'], [3600, 'hour'], [60, 'minute']]) {
    if (seconds >= size) {
      const count = Math.floor(seconds / size);
      return `${count} ${unit}${count === 1 ? '' : 's'} ago`;
    }
  }
}

// ── Dialogs ──

const showSheet = id => pick('#' + id).classList.remove('is-hidden');
const hideSheet = id => pick('#' + id).classList.add('is-hidden');

pickAll('.overlay').forEach(overlay => {
  // Backdrop clicks close; clicks inside the dialog do not.
  overlay.addEventListener('click', event => {
    if (event.target === overlay) overlay.classList.add('is-hidden');
  });
});
pickAll('.sheet-close, [data-close]').forEach(button =>
  button.addEventListener('click', () => button.closest('.overlay').classList.add('is-hidden')));
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') pickAll('.overlay').forEach(o => o.classList.add('is-hidden'));
});

// ── Data ──

async function refresh() {
  try {
    const [connectors, routes] = await Promise.all([
      request('GET', '/connectors'),
      request('GET', '/resources'),
    ]);
    state.connectors = connectors || [];
    state.routes = routes || [];
    drawConnectors();
    drawRoutes();
    return true;
  } catch (error) {
    if (error?.status === 401) window.location.href = '/login.html';
    return false;
  }
}

// ── Views ──

function showView(name) {
  pickAll('.tab').forEach(tab => tab.classList.toggle('is-current', tab.dataset.view === name));
  pickAll('.view').forEach(view => view.classList.toggle('is-hidden', view.id !== 'view-' + name));
}

pickAll('.tab').forEach(tab => tab.addEventListener('click', () => showView(tab.dataset.view)));

function emptyState(title, hint) {
  return `<div class="empty"><strong>${html(title)}</strong>${html(hint)}</div>`;
}

// ── Connectors ──

const connectionText = c => c.transport ? 'Connected over ' + c.transport : 'Offline';

function drawConnectors() {
  const list = pick('#connector-list');
  if (!state.connectors.length) {
    list.innerHTML = emptyState('No connectors yet', 'Create one to reach services on another network.');
    return;
  }
  const rows = state.connectors.map(c => `
    <div class="list-row" data-id="${html(c.id)}">
      <div class="col col-primary">${html(c.name)}</div>
      <div class="col"><span class="link-state"><span class="link-dot${c.transport ? ' is-up' : ''}"></span>${html(connectionText(c))}</span></div>
      <div class="col col-muted">${html(timeAgo(c.last_seen))}</div>
    </div>`).join('');
  list.innerHTML = `
    <div class="list list-connectors">
      <div class="list-head"><div>Name</div><div>Status</div><div>Last seen</div></div>
      ${rows}
    </div>`;
  list.querySelectorAll('.list-row').forEach(row =>
    row.addEventListener('click', () => showConnector(row.dataset.id)));
}

function showConnector(id) {
  const c = state.connectors.find(c => c.id === id);
  if (!c) return;
  state.connectorId = id;
  pick('#connector-title').textContent = c.name;
  pick('#connector-state').textContent = connectionText(c);
  const seen = pick('#connector-heartbeat');
  seen.textContent = timeAgo(c.last_seen);
  seen.title = c.last_seen ? new Date(c.last_seen).toLocaleString() : '';
  pick('#connector-wss').checked = !!c.force_wss;
  showSheet('sheet-connector');
}

pick('#connector-wss').addEventListener('change', async event => {
  const on = event.target.checked;
  try {
    // The server drops the live session so the connector reconnects with the new transport.
    await request('PUT', '/connectors/' + state.connectorId, { force_wss: on });
    refresh();
  } catch (error) {
    event.target.checked = !on;
    alert(error.message || 'Could not update the connector');
  }
});

function presentInstallCommand(command) {
  pick('#install-command').textContent = command;
  pick('#copy-install').textContent = 'Copy';
  showSheet('sheet-install');
}

pick('#copy-install').addEventListener('click', event => {
  const command = pick('#install-command').textContent.trim();
  navigator.clipboard.writeText(command).then(
    () => { event.target.textContent = 'Copied'; },
    () => { event.target.textContent = 'Copy failed'; });
});

pick('#rotate-token').addEventListener('click', async () => {
  if (!confirm('Regenerate the token? The connector disconnects until it is reinstalled with the new command.')) return;
  try {
    const issued = await request('POST', '/connectors/' + state.connectorId + '/token');
    hideSheet('sheet-connector');
    presentInstallCommand(issued.install_command);
    refresh();
  } catch (error) {
    alert('Failed: ' + error.message);
  }
});

pick('#remove-connector').addEventListener('click', async () => {
  const inUse = state.routes.filter(r => r.connector_id === state.connectorId);
  if (inUse.length) {
    alert('Still used by ' + inUse.map(r => r.subdomain).join(', ') + '. Move or delete those routes first.');
    return;
  }
  if (!confirm('Delete this connector?')) return;
  try {
    await request('DELETE', '/connectors/' + state.connectorId);
    hideSheet('sheet-connector');
    refresh();
  } catch (error) {
    alert('Failed: ' + error.message);
  }
});

pick('#add-connector').addEventListener('click', () => {
  pick('#add-connector-form').reset();
  showSheet('sheet-add-connector');
  pick('#add-connector-name').focus();
});

pick('#add-connector-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = event.target.querySelector('[type="submit"]');
  submit.disabled = true;
  try {
    const name = pick('#add-connector-name').value.trim();
    if (!name) return;
    const created = await request('POST', '/connectors', { name });
    hideSheet('sheet-add-connector');
    presentInstallCommand(created.install_command);
    refresh();
  } catch (error) {
    alert(error.status === 409 ? 'A connector with that name already exists.' : error.message || 'Failed');
  } finally {
    submit.disabled = false;
  }
});

// ── Routes ──

function connectorName(id) {
  if (!id) return 'This server';
  return state.connectors.find(c => c.id === id)?.name ?? 'Unknown';
}

function drawRoutes() {
  const list = pick('#route-list');
  if (!state.routes.length) {
    list.innerHTML = emptyState('No routes yet', 'Add one to publish a service under a subdomain.');
    return;
  }
  const rows = state.routes.map(r => `
    <div class="list-row" data-id="${html(r.id)}">
      <div class="col col-primary">${html(r.subdomain)}</div>
      <div class="col col-code">${html(r.target)}</div>
      <div class="col"><span class="tag">${html(connectorName(r.connector_id))}</span></div>
      <div class="col col-end"><label class="switch" data-id="${html(r.id)}"><input type="checkbox" aria-label="Enabled"${r.enabled ? ' checked' : ''}><span class="switch-rail"></span></label></div>
    </div>`).join('');
  list.innerHTML = `
    <div class="list list-routes">
      <div class="list-head"><div>Subdomain</div><div>Target</div><div>Via</div><div class="col-end">On</div></div>
      ${rows}
    </div>`;
  list.querySelectorAll('.list-row').forEach(row =>
    row.addEventListener('click', () => showRoute(row.dataset.id)));
  list.querySelectorAll('.switch').forEach(toggle => {
    toggle.addEventListener('click', event => event.stopPropagation());
    const box = toggle.querySelector('input');
    box.addEventListener('change', () => setEnabled(toggle.dataset.id, box.checked));
  });
}

async function setEnabled(id, enabled) {
  const route = state.routes.find(r => r.id === id);
  if (!route) return;
  const before = route.enabled;
  route.enabled = enabled;
  try {
    await request('PUT', '/resources/' + id, { enabled });
  } catch {
    route.enabled = before;
    drawRoutes();
  }
}

// `URL` normalizes the hostname first: lowercase, dotted-quad, bracketed IPv6.
const isThisHost = hostname =>
  hostname === 'localhost' || hostname === '[::1]' || /^127\.\d+\.\d+\.\d+$/.test(hostname);

function targetProblem(target, connectorId) {
  let url;
  try { url = new URL(target); } catch { return 'Enter a full URL, like http://127.0.0.1:8080'; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'The target must use http:// or https://';
  if ((url.pathname && url.pathname !== '/') || url.search || url.hash)
    return 'The target is an origin only: no path or query';
  if (!connectorId && !isThisHost(url.hostname))
    return 'Without a connector the target must be on this server (127.0.0.1, ::1 or localhost).';
  // A connector reaches the origin over plain TCP.
  if (connectorId && url.protocol !== 'http:') return 'Targets behind a connector must use http://';
  return null;
}

function syncOriginHints() {
  const viaConnector = !!pick('#route-via').value;
  pick('#route-origin').placeholder = viaConnector ? 'http://192.168.1.20:8080' : 'http://127.0.0.1:8080';
  pick('#route-origin-help').textContent = viaConnector
    ? 'An address the connector can reach on its network.'
    : 'A service on this server: 127.0.0.1, ::1 or localhost.';
}

pick('#route-via').addEventListener('change', syncOriginHints);

// A route may still name a connector that has since been deleted.
function connectorOptions(selectedId) {
  const options = [{ id: '', name: 'This server' }, ...state.connectors];
  if (selectedId && !state.connectors.some(c => c.id === selectedId)) {
    options.push({ id: selectedId, name: 'Unknown connector (' + selectedId.slice(0, 8) + ')' });
  }
  pick('#route-via').innerHTML = options
    .map(o => `<option value="${html(o.id)}">${html(o.name)}</option>`).join('');
  pick('#route-via').value = selectedId || '';
  syncOriginHints();
}

function openEditor(route) {
  state.routeId = route?.id ?? null;
  pick('#route-form').reset();
  connectorOptions(route?.connector_id);
  pick('#route-subdomain').value = route?.subdomain ?? '';
  pick('#route-origin').value = route?.target ?? '';
  pick('#route-allow').value = (route?.allowed_client_cidrs || []).join(', ');
  pick('#route-title').textContent = route ? route.subdomain : 'New route';
  pick('#route-save').textContent = route ? 'Save' : 'Create';
  pick('#remove-route').classList.toggle('is-hidden', !route);
  showSheet('sheet-route');
}

function showRoute(id) {
  const route = state.routes.find(r => r.id === id);
  if (route) openEditor(route);
}

pick('#add-route').addEventListener('click', () => {
  openEditor(null);
  pick('#route-subdomain').focus();
});

pick('#route-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = event.target.querySelector('[type="submit"]');
  submit.disabled = true;
  try {
    const subdomain = pick('#route-subdomain').value.trim();
    const target = pick('#route-origin').value.trim();
    const connector_id = pick('#route-via').value || null;
    const problem = targetProblem(target, connector_id);
    if (problem) { alert(problem); return; }

    const body = { subdomain, target, connector_id, allowed_client_cidrs: splitList(pick('#route-allow').value) };
    await (state.routeId
      ? request('PUT', '/resources/' + state.routeId, body)
      : request('POST', '/resources', body));

    hideSheet('sheet-route');
    refresh();
  } catch (error) {
    alert(error.status === 409 ? 'That subdomain is already in use.' : error.message || 'Failed');
  } finally {
    submit.disabled = false;
  }
});

pick('#remove-route').addEventListener('click', async () => {
  if (!confirm('Delete this route?')) return;
  try {
    await request('DELETE', '/resources/' + state.routeId);
    hideSheet('sheet-route');
    refresh();
  } catch (error) {
    alert('Failed: ' + error.message);
  }
});

// ── Start ──

refresh().then(ok => { if (!ok) window.location.href = '/login.html'; });
setInterval(refresh, 30000);
