'use strict';

// Everything a sender put in a delivery is untrusted: it is only ever
// written with textContent, never as HTML.

const $ = id => document.getElementById(id);
const API = '/api/private/v1';
const PAGE = 100;
const state = {
  key: '', session: 0, view: 'overview', overview: null, channels: [],
  tokens: { sender: [], consumer: [] }, events: [], nextBefore: null,
  filter: {}, detail: null, detailTab: 'payload', confirmation: null,
};

const number = value => Number(value || 0).toLocaleString();
const time = value => value ? new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
const bytes = value => value < 1024 ? `${value} B` : value < 1048576 ? `${(value / 1024).toFixed(1)} KB` : `${(value / 1048576).toFixed(1)} MB`;
const text = (id, value) => { $(id).textContent = value; };
const element = (tag, value, className) => { const node = document.createElement(tag); if (value !== undefined && value !== null) node.textContent = value; if (className) node.className = className; return node; };
const badge = (value, tone) => element('span', value, `badge ${tone || ''}`);
const cell = (...nodes) => { const td = element('td'); for (const node of nodes) td.append(typeof node === 'string' ? document.createTextNode(node) : node); return td; };
const lines = (main, sub, mono = false) => { const div = element('div', main, mono ? 'mono' : ''); if (sub) div.append(element('span', sub, 'subline')); return div; };
const emptyRow = (target, columns, message) => { const row = element('tr', undefined, 'empty-row'); const td = cell(message); td.colSpan = columns; row.append(td); $(target).replaceChildren(row); };
const button = (label, callback, className = 'action') => { const node = element('button', label, className); node.type = 'button'; node.addEventListener('click', event => { event.stopPropagation(); task(node, callback); }); return node; };
const publicURL = () => state.overview?.public_url || `${location.protocol}//${location.host.replace(/-admin(?=[.:]|$)/, '')}`;

const KINDS = {
  sender: {
    eyebrow: 'WHO MAY POST', title: 'Sender tokens', heading: 'Sender tokens',
    intro: 'A sender token is also a webhook signing secret. Paste it as the hook’s secret; the sink identifies the token by the signature.',
    usage: value => [
      ['GitHub or Jira hook', 'Set the hook’s secret to this value. Deliveries are signed with it.'],
      ['GitLab hook', 'Set the hook’s secret token to this value.'],
      ['Script', `curl -X POST ${publicURL()}/hooks/<channel> -H 'Authorization: Bearer ${value}' -d '{}'`],
    ],
  },
  consumer: {
    eyebrow: 'WHO MAY READ', title: 'Consumer tokens', heading: 'Consumer tokens',
    intro: 'Consumers read events with a consumer token as a bearer token. Only a fingerprint of the value is stored.',
    usage: value => [
      ['Read new events', `curl -H 'Authorization: Bearer ${value}' '${publicURL()}/events?after=0&wait=30'`],
    ],
  },
};

function notice(message, error = false) {
  text('notice', message); $('notice').classList.toggle('error', error); $('notice').hidden = !message;
}

async function task(control, callback, errorID) {
  if (control) control.disabled = true;
  if (errorID) text(errorID, '');
  try { await callback(); }
  catch (error) {
    if (!state.key) text('connect-error', error.message);
    else if (errorID) text(errorID, error.message);
    else notice(error.message, true);
  }
  finally { if (control) control.disabled = false; }
}

async function api(path, method = 'GET', body, raw = false) {
  const session = state.session;
  const headers = { Authorization: `Bearer ${state.key}` };
  if (!raw) headers.Accept = 'application/json';
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let response;
  try { response = await fetch(API + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'omit', cache: 'no-store' }); }
  catch (_) { throw new Error('Could not reach the sink. Check the connection and try again.'); }
  if (session !== state.session) throw new Error('Connection closed.');
  if (response.status === 401) { disconnect(); throw new Error('The admin key was rejected. Enter a valid key to reconnect.'); }
  if (raw && response.ok) return response.text();
  const value = await response.json().catch(() => null);
  if (session !== state.session) throw new Error('Connection closed.');
  if (!response.ok) throw new Error(value?.message || `Request failed (${response.status}).`);
  return value;
}

async function connect(key) {
  state.key = key; state.session += 1;
  try { await api('/overview'); }
  catch (error) { state.key = ''; throw error; }
  $('admin-key').value = '';
  $('connect-screen').hidden = true; $('app').hidden = false;
  await refresh();
}

function disconnect() {
  state.key = ''; state.session += 1; state.overview = null; state.events = [];
  $('app').hidden = true; $('connect-screen').hidden = false; notice('');
}

async function refresh() {
  const [overview, channels, senders, consumers] = await Promise.all([
    api('/overview'), api('/channels'), api('/tokens?kind=sender'), api('/tokens?kind=consumer'),
  ]);
  state.overview = overview; state.channels = channels.channels;
  state.tokens = { sender: senders.items, consumer: consumers.items };
  renderOverview(); renderFilterOptions();
  if (state.view === 'events') await loadEvents();
  if (state.view === 'senders' || state.view === 'consumers') renderTokens();
  text('updated-at', `Updated ${time(new Date().toISOString())}`);
  $('health-dot').className = 'status-dot'; text('health-text', 'Connected');
}

function show(view) {
  state.view = view;
  for (const item of document.querySelectorAll('.nav-item')) {
    const active = item.dataset.view === view;
    item.classList.toggle('active', active);
    if (active) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
  }
  $('overview-view').hidden = view !== 'overview';
  $('events-view').hidden = view !== 'events';
  $('tokens-view').hidden = view !== 'senders' && view !== 'consumers';
  notice('');
  if (view === 'events') task(null, loadEvents);
  if (view === 'senders' || view === 'consumers') renderTokens();
}

function renderOverview() {
  const o = state.overview;
  text('stat-events', number(o.events.total));
  text('stat-seq', number(o.events.latest_seq));
  text('stat-senders', number(o.tokens.sender));
  text('stat-consumers', number(o.tokens.consumer));
  text('event-count', number(o.events.total));
  text('sender-count', number(o.tokens.sender));
  text('consumer-count', number(o.tokens.consumer));
  text('version', `webhook-sink ${o.version}`);
  $('reveal-mode').hidden = !o.insecure_reveal_tokens;
  const base = publicURL();
  text('hook-url', `${base}/hooks/<channel>`);
  text('send-example', `curl -X POST '${base}/hooks/demo' \\\n  -H 'Authorization: Bearer <sender token>' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"hello":"world"}'`);
  text('consume-example', `curl -H 'Authorization: Bearer <consumer token>' \\\n  '${base}/events?channel=demo&after=0&wait=30'`);
  for (const [target, items] of [['source-facets', o.events.sources], ['type-facets', o.events.types], ['host-facets', o.events.hosts], ['repo-facets', o.events.repos]]) {
    const nodes = items.map(item => badge(`${item.name} · ${number(item.count)}`));
    $(target).replaceChildren(...(nodes.length ? nodes : [element('p', 'Nothing yet.', 'empty-inline')]));
  }
  if (!state.channels.length) { emptyRow('channel-rows', 5, 'No events yet. Point a hook at a channel to start.'); return; }
  $('channel-rows').replaceChildren(...state.channels.map(channel => {
    const row = element('tr');
    const actions = element('div', undefined, 'actions');
    actions.append(
      button('View events', () => { state.filter = { channel: channel.channel }; applyFilterToForm(); show('events'); }),
      button('Reset', () => confirmAction(`Reset ${channel.channel}?`, `Deletes the ${number(channel.count)} stored events on this channel. Sequence numbers are not reused, so consumers' cursors stay valid.`, 'Reset channel', async () => {
        const result = await api(`/events?channel=${encodeURIComponent(channel.channel)}`, 'DELETE');
        notice(`Deleted ${number(result.deleted)} events from ${channel.channel}.`); await refresh();
      }), 'danger-text'),
    );
    row.append(cell(lines(channel.channel, undefined, true)), cell(number(channel.count)), cell(`#${channel.latest_seq}`), cell(time(channel.latest_received_at)), cell(actions));
    return row;
  }));
}

function options(select, placeholder, values) {
  const current = select.value;
  const nodes = [element('option', placeholder)];
  nodes[0].value = '';
  for (const [value, label] of values) { const option = element('option', label); option.value = value; nodes.push(option); }
  select.replaceChildren(...nodes);
  if ([...select.options].some(o => o.value === current)) select.value = current;
}

function renderFilterOptions() {
  const form = $('event-filters');
  options(form.elements.channel, 'All channels', state.channels.map(c => [c.channel, c.channel]));
  options(form.elements.source, 'All sources', state.overview.events.sources.map(s => [s.name, s.name]));
  options(form.elements.event, 'All types', state.overview.events.types.map(t => [t.name, t.name]));
  options(form.elements.sender, 'All senders', state.tokens.sender.map(t => [t.id, t.status === 'revoked' ? `${t.name} (revoked)` : t.name]));
  options(form.elements.host, 'All hosts', state.overview.events.hosts.map(h => [h.name, h.name]));
  $('repo-options').replaceChildren(...state.overview.events.repos.map(r => { const option = element('option'); option.value = r.name; return option; }));
  applyFilterToForm();
}

function applyFilterToForm() {
  const form = $('event-filters');
  form.elements.repo.value = state.filter.repo || '';
  for (const name of ['channel', 'source', 'event', 'sender', 'host']) {
    const select = form.elements[name];
    const wanted = state.filter[name] || '';
    if (wanted && ![...select.options].some(o => o.value === wanted)) {
      const option = element('option', wanted); option.value = wanted; select.append(option);
    }
    select.value = wanted;
  }
}

function filterQuery(extra = {}) {
  const params = new URLSearchParams({ limit: String(PAGE), ...extra });
  for (const [name, value] of Object.entries(state.filter)) if (value) params.set(name, value);
  return params.toString();
}

async function loadEvents(more = false) {
  const extra = more && state.nextBefore ? { before: String(state.nextBefore) } : {};
  const page = await api(`/events?${filterQuery(extra)}`);
  state.events = more ? state.events.concat(page.events) : page.events;
  state.nextBefore = page.next_before;
  renderEvents();
}

function senderLabel(sender) {
  if (!sender) return lines('—');
  return lines(sender.name || sender.token_id, sender.method, false);
}

function renderEvents() {
  const filtered = Object.values(state.filter).some(Boolean);
  text('events-note', `${number(state.events.length)} shown${filtered ? ' · filtered' : ''}`);
  $('load-more').hidden = !state.nextBefore;
  if (!state.events.length) { emptyRow('event-rows', 7, filtered ? 'No events match these filters.' : 'No events yet.'); return; }
  $('event-rows').replaceChildren(...state.events.map(event => {
    const row = element('tr', undefined, 'clickable');
    row.tabIndex = 0;
    row.addEventListener('click', () => task(null, () => openEvent(event.seq)));
    row.addEventListener('keydown', e => { if (e.key === 'Enter') task(null, () => openEvent(event.seq)); });
    row.append(
      cell(lines(`#${event.seq}`, undefined, true)),
      cell(time(event.received_at)),
      cell(lines(event.channel, undefined, true)),
      cell(lines(event.source, event.event || '—')),
      cell(lines(event.repo || '—', event.host, Boolean(event.repo))),
      cell(senderLabel(event.sender)),
      cell(bytes(event.size)),
    );
    return row;
  }));
}

async function openEvent(seq) {
  state.detail = await api(`/events/${seq}`);
  state.detailTab = 'payload';
  const d = state.detail;
  text('event-title', `#${d.seq} · ${d.source}${d.event ? ` · ${d.event}` : ''}`);
  const meta = [
    ['Channel', d.channel], ['Received', time(d.received_at)], ['Size', bytes(d.size)],
    ['Host', d.host || '—'], ['Repository', d.repo || '—'],
    ['Delivery ID', d.delivery_id || '—'], ['Content type', d.content_type || '—'],
    ['Sender', d.sender ? `${d.sender.name || d.sender.token_id} (${d.sender.method})` : '—'],
  ];
  $('event-meta').replaceChildren(...meta.map(([label, value]) => { const div = element('div'); div.append(element('dt', label), element('dd', value)); return div; }));
  await renderDetail();
  $('event-dialog').showModal();
}

async function renderDetail() {
  const d = state.detail;
  for (const tab of document.querySelectorAll('[data-tab]')) tab.classList.toggle('active', tab.dataset.tab === state.detailTab);
  let body;
  if (state.detailTab === 'headers') body = JSON.stringify(d.headers, null, 2);
  else if (state.detailTab === 'raw') body = await api(`/events/${d.seq}/raw`, 'GET', undefined, true);
  else if ('payload' in d) body = JSON.stringify(d.payload, null, 2);
  else if ('body' in d) body = d.body;
  else body = `(binary, base64)\n${d.body_base64}`;
  text('event-body', body === '' ? '(empty body)' : body);
}

function renderTokens() {
  const kind = state.view === 'senders' ? 'sender' : 'consumer';
  const copy = KINDS[kind];
  text('tokens-eyebrow', copy.eyebrow); text('tokens-title', copy.title); text('tokens-intro', copy.intro); text('tokens-heading', copy.heading);
  const reveal = Boolean(state.overview?.insecure_reveal_tokens);
  $('reveal-warning').hidden = !reveal;
  if (kind === 'consumer' && reveal) text('tokens-intro', 'Consumers read events with a consumer token as a bearer token. In reveal mode the value is stored, so it can be shown again.');
  const items = state.tokens[kind];
  text('tokens-note', `${number(items.filter(t => t.status === 'active').length)} active · ${number(items.length)} total`);
  if (!items.length) { emptyRow('token-rows', 6, `No ${kind} tokens yet. Issue one to get started.`); return; }
  $('token-rows').replaceChildren(...items.map(token => {
    const row = element('tr');
    const status = element('div', undefined, 'actions');
    if (token.is_default) status.append(badge('Default', 'good'));
    status.append(token.status === 'revoked' ? badge('Revoked', 'bad') : badge('Active'));
    const actions = element('div', undefined, 'actions');
    if (token.status === 'active' && reveal && token.value_stored) {
      actions.append(
        button('Show', async () => showSecret(await api(`/tokens/${token.id}/value`), 'Token value', true)),
        button('Copy', async () => { const result = await api(`/tokens/${token.id}/value`); await copyText(result.value); notice(`Copied ${token.name}'s value.`); }),
      );
    } else if (token.status === 'active' && reveal) {
      actions.append(element('span', 'Not stored; rotate to reveal', 'hint'));
    }
    if (token.status === 'active') {
      actions.append(
        button('Rotate', () => confirmAction(`Rotate ${token.name}?`, kind === 'sender'
          ? 'Issues a new value. Hooks still signing with the old value are rejected until their secret is updated.'
          : 'Issues a new value. Consumers using the old value are rejected until they switch.', 'Rotate token', async () => {
          const result = await api(`/tokens/${token.id}/rotate`, 'POST');
          await refresh(); showSecret(result, 'Token rotated');
        })),
        button('Revoke', () => confirmAction(`Revoke ${token.name}?`, `${kind === 'sender' ? 'Deliveries using it' : 'Consumers using it'} are rejected from now on. This cannot be undone.${token.is_default ? ' This is the default token: a restart does not bring it back.' : ''}`, 'Revoke token', async () => {
          await api(`/tokens/${token.id}/revoke`, 'POST');
          notice(`Revoked ${token.name}.`); await refresh();
        }), 'danger-text'),
      );
    }
    row.append(
      cell(lines(token.name, token.description)),
      cell(lines(`${token.prefix}…`, token.id, true)),
      cell(status),
      cell(time(token.created_at)),
      cell(token.status === 'revoked' ? lines(time(token.last_used_at), `revoked ${time(token.revoked_at)}`) : time(token.last_used_at)),
      cell(actions),
    );
    return row;
  }));
}

async function copyText(value) {
  try { await navigator.clipboard.writeText(value); }
  catch (_) { throw new Error('The browser blocked clipboard access. Use Show and copy the value from there.'); }
}

function showSecret(result, title, revealed = false) {
  text('secret-title', title);
  text('secret-eyebrow', revealed ? 'INSECURE REVEAL MODE' : 'SHOWN ONCE');
  text('secret-note', revealed
    ? 'Shown because insecure reveal mode is on. Treat it as a credential.'
    : 'Copy the value now. It cannot be shown again; rotate the token if it is lost.');
  $('issued-secret').value = result.value;
  const usage = KINDS[result.token.kind].usage(result.value).flatMap(([label, value]) => [element('h3', label), value.startsWith('curl') ? element('pre', value) : element('p', value, 'hint')]);
  $('secret-usage').replaceChildren(...usage);
  $('secret-dialog').showModal();
}

function confirmAction(title, message, label, action) {
  text('confirm-title', title); text('confirm-text', message); text('confirm-action', label);
  state.confirmation = action;
  $('confirm-dialog').showModal();
}

document.addEventListener('DOMContentLoaded', () => {
  text('origin', location.host);
  $('connect-form').addEventListener('submit', event => {
    event.preventDefault();
    const control = event.submitter;
    task(control, () => connect($('admin-key').value.trim()), 'connect-error');
  });
  $('disconnect').addEventListener('click', disconnect);
  $('refresh').addEventListener('click', event => task(event.currentTarget, refresh));
  for (const item of document.querySelectorAll('.nav-item')) item.addEventListener('click', () => show(item.dataset.view));
  for (const close of document.querySelectorAll('[data-close]')) close.addEventListener('click', () => $(close.dataset.close).close());
  $('event-filters').addEventListener('submit', event => {
    event.preventDefault();
    const form = event.currentTarget;
    state.filter = Object.fromEntries(['channel', 'source', 'event', 'sender', 'host', 'repo'].map(name => [name, form.elements[name].value.trim()]).filter(([, v]) => v));
    task(event.submitter, () => loadEvents());
  });
  $('load-more').addEventListener('click', event => task(event.currentTarget, () => loadEvents(true)));
  for (const tab of document.querySelectorAll('[data-tab]')) tab.addEventListener('click', () => { state.detailTab = tab.dataset.tab; task(tab, renderDetail); });
  $('reset-all').addEventListener('click', () => confirmAction('Reset all events?', 'Deletes every stored event on every channel. Tokens are kept, and sequence numbers are not reused.', 'Reset all', async () => {
    const result = await api('/events', 'DELETE');
    notice(`Deleted ${number(result.deleted)} events.`); await refresh();
  }));
  $('confirm-action').addEventListener('click', event => {
    const action = state.confirmation; state.confirmation = null;
    task(event.currentTarget, async () => { $('confirm-dialog').close(); if (action) await action(); });
  });
  $('issue-token').addEventListener('click', () => {
    const kind = state.view === 'senders' ? 'sender' : 'consumer';
    $('token-form').reset(); text('token-error', '');
    text('token-dialog-eyebrow', kind === 'sender' ? 'NEW SENDER TOKEN' : 'NEW CONSUMER TOKEN');
    $('token-dialog').showModal();
  });
  $('token-form').addEventListener('submit', event => {
    event.preventDefault();
    const form = event.currentTarget;
    const kind = state.view === 'senders' ? 'sender' : 'consumer';
    task(event.submitter, async () => {
      const result = await api('/tokens', 'POST', { kind, name: form.elements.name.value, description: form.elements.description.value });
      $('token-dialog').close(); await refresh(); showSecret(result, 'Token issued');
    }, 'token-error');
  });
  $('copy-secret').addEventListener('click', async () => {
    const input = $('issued-secret');
    try { await navigator.clipboard.writeText(input.value); text('copy-secret', 'Copied'); }
    catch (_) { input.select(); text('copy-secret', 'Press Ctrl+C to copy'); }
    setTimeout(() => text('copy-secret', 'Copy value'), 2000);
  });
});
