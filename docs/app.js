'use strict';
(() => {
  const TZ = 'America/Chicago';
  const $ = s => document.querySelector(s);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const httpUrl = u => (typeof u === 'string' && /^https?:\/\/[^\s"'<>]+$/i.test(u)) ? u : null;
  const ICON = {
    cal: '<svg viewBox="0 0 24 24"><rect x="3.5" y="5" width="17" height="15" rx="2"/><path d="M3.5 10h17M8 3v4M16 3v4"/></svg>',
    back: '<svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>',
    arrow: '<svg viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
    print: '<svg viewBox="0 0 24 24"><path d="M7 9V3h10v6M7 17H5a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-2"/><rect x="7" y="14" width="10" height="7" rx="1"/></svg>',
    users: '<svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7M21.5 20a6.5 6.5 0 0 0-4-6"/></svg>',
    clock: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
    doc: '<svg viewBox="0 0 24 24"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/></svg>',
    info: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>',
    help: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6V14M12 17h.01"/></svg>',
    target: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/></svg>',
    notes: '<svg viewBox="0 0 24 24"><path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16v4z"/><path d="M13.5 6.5l4 4"/></svg>',
    flag: '<svg viewBox="0 0 24 24"><path d="M5 21V4M5 4h11l-2 4 2 4H5"/></svg>',
    list: '<svg viewBox="0 0 24 24"><path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01"/></svg>',
    link: '<svg viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg>',
  };

  // ---------- crypto (identical to meeting-prep) ----------
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  async function fetchBlob() { const r = await fetch('data.enc.json', { cache: 'no-store' }); if (!r.ok) throw new Error('Could not load encrypted data.'); return r.json(); }
  async function decrypt(blob, pass) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: unb64(blob.salt), iterations: blob.iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  // ---------- dates (Central) ----------
  const fmt = (d, o) => new Intl.DateTimeFormat('en-US', { timeZone: TZ, ...o }).format(d);
  const todayIso = () => { const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date()).map(x => [x.type, x.value])); return `${p.year}-${p.month}-${p.day}`; };
  const isoDate = iso => new Date(iso + 'T12:00:00Z');
  const dfmt = (iso, o) => new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', ...o }).format(isoDate(iso));
  const tzAbbr = d => fmt(d, { timeZoneName: 'short' }).split(' ').pop();
  function dayLabel(iso) {
    const t = todayIso(); const diff = Math.round((isoDate(iso) - isoDate(t)) / 864e5);
    return diff === 0 ? 'Today' : diff === 1 ? 'Tomorrow' : diff === -1 ? 'Yesterday' : dfmt(iso, { weekday: 'long' });
  }

  // ---------- status ----------
  const CLS = { 'Research Needed': 'todo', 'Draft Ready': 'draft', 'Approved': 'approved', 'Sent Confirmed': 'ready', 'Replied': 'ready', 'Next Action': 'next', 'On Hold': 'hold' };
  const READY = s => ['Draft Ready', 'Approved', 'Next Action'].includes(s);
  const ACTIVE = s => !['On Hold', 'Sent Confirmed', 'Replied'].includes(s);
  const overdue = c => c.dueIso && ACTIVE(c.status) && c.status !== 'Research Needed' && c.dueIso < todayIso();
  const badge = (s, extra = '') => `<span class="status ${CLS[s] || 'todo'}">${esc(s)}${extra}</span>`;
  const badgeFor = c => overdue(c) ? `<span class="status urgent">Overdue · ${esc(c.status)}</span>` : badge(c.status);
  const RANK = ['Draft Ready', 'Approved', 'Next Action', 'Research Needed', 'Replied', 'Sent Confirmed', 'On Hold'];

  // ---------- safe inline markdown ----------
  function md(src) {
    const ph = []; const hold = html => `\u0000${ph.push(html) - 1}\u0000`;
    let s = String(src ?? '');
    s = s.replace(/\\([\\`*_[\]()#+\-.!|~>$<{}^])/g, (_, c) => hold(esc(c)));
    s = s.replace(/`([^`]+)`/g, (_, c) => hold(`<code>${esc(c)}</code>`));
    s = s.replace(/\[([^\]]*)\]\(([^)\s]+)\)/g, (_, t, u) => { const url = httpUrl(u); const inner = fmtInline(esc(t || u));
      return hold(url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${inner}</a>` : inner); });
    s = s.replace(/https?:\/\/[^\s<>"')\]]+[^\s<>"')\].,;:]/g, u => { const url = httpUrl(u); return hold(url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(u.replace(/^https?:\/\/(www\.)?/, ''))}</a>` : esc(u)); });
    s = fmtInline(esc(s));
    return s.replace(/\u0000(\d+)\u0000/g, (_, i) => ph[+i]);
  }
  function fmtInline(h) {
    return h.replace(/\*\*(?=[^\s*])(.+?)(?<=[^\s*])\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[^*\w])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?!\*)/g, '$1<em>$2</em>')
      .replace(/~~(?=\S)(.+?)(?<=\S)~~/g, '<s>$1</s>');
  }
  const LABEL_RE = /^\*\*([^*]+?):\*\*\s*(.*)$/;

  // ---------- blocks (same component styles as meeting-prep detail view) ----------
  function renderBlocks(blocks) {
    let html = '', i = 0;
    while (i < blocks.length) {
      const b = blocks[i];
      const group = t => { const g = []; while (i < blocks.length && blocks[i].type === t) g.push(blocks[i++]); return g; };
      if (b.type === 'heading') { html += `<h3 class="d-sub">${md(b.text)}</h3>`; i++; continue; }
      if (b.type === 'bullet') {
        const g = group('bullet');
        html += `<ul class="d-list">${g.map(x => { const m = x.text.match(LABEL_RE); return `<li>${m ? `<strong>${md(m[1])}:</strong> ${md(m[2])}` : md(x.text)}${x.children?.length ? renderBlocks(x.children) : ''}</li>`; }).join('')}</ul>`; continue;
      }
      if (b.type === 'numbered') { const g = group('numbered'); html += `<ol class="d-list">${g.map(x => `<li>${md(x.text)}${x.children?.length ? renderBlocks(x.children) : ''}</li>`).join('')}</ol>`; continue; }
      if (b.type === 'paragraph') {
        const g = []; while (i < blocks.length && blocks[i].type === 'paragraph' && LABEL_RE.test(blocks[i].text)) g.push(blocks[i++]);
        if (g.length) { html += `<dl class="kv-grid">${g.map(x => { const m = x.text.match(LABEL_RE); return `<dt>${md(m[1])}</dt><dd>${md(m[2]) || '<span class="ph">—</span>'}</dd>`; }).join('')}</dl>`; continue; }
        html += `<p>${md(b.text)}</p>`; i++; continue;
      }
      i++;
      if (b.type === 'quote') html += `<blockquote>${md(b.text)}</blockquote>`;
      else if (b.type === 'table') {
        const rows = b.rows || []; const head = b.header && rows.length ? rows[0] : null; const body = head ? rows.slice(1) : rows;
        html += `<div class="table-wrap"><table>${head ? `<thead><tr>${head.map(c => `<th>${md(c)}</th>`).join('')}</tr></thead>` : ''}<tbody>${body.map(r => `<tr>${r.map(c => `<td>${md(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
      }
    }
    return html;
  }
  const secIcon = h => /queue|rank/i.test(h) ? ICON.list : /signal/i.test(h) ? ICON.target : /blocker|needs/i.test(h) ? ICON.flag : /recap/i.test(h) ? ICON.info : /card|contact/i.test(h) ? ICON.users : /check|duplicate/i.test(h) ? ICON.help : ICON.doc;
  const section = (heading, inner, count = '') => `<section class="d-sec">${heading ? `<header class="d-sec-head"><span class="d-ico">${secIcon(heading)}</span><h2>${md(heading)}</h2>${count ? `<span class="d-count">${esc(count)}</span>` : ''}</header>` : ''}<div class="d-body">${inner}</div></section>`;
  const emptyState = (t, b) => `<div class="empty-state"><div class="ill">${ICON.cal}</div><h3>${esc(t)}</h3><p>${esc(b)}</p></div>`;

  // ---------- data helpers ----------
  let DATA = null;
  const people = () => {
    const m = new Map();
    for (const c of DATA.contacts) { if (!m.has(c.personKey)) m.set(c.personKey, { key: c.personKey, rid: c.id, account: c.account, name: c.contact, role: c.role, rows: [] }); m.get(c.personKey).rows.push(c); }
    for (const p of m.values()) {
      p.status = p.rows.map(r => r.status).sort((a, b) => RANK.indexOf(a) - RANK.indexOf(b))[0];
      p.next = p.rows.find(r => r.actionCode === 'CONNECT') || p.rows[0];
      p.overdue = p.rows.some(overdue);
    }
    return [...m.values()];
  };
  const accounts = () => { const order = DATA.campaign.accounts; const ps = people(); const names = [...new Set([...order, ...ps.map(p => p.account)])];
    return names.map(a => ({ name: a, people: ps.filter(p => p.account === a) })); };
  const statCounts = rows => Object.fromEntries(DATA.statuses.map(s => [s, rows.filter(r => r.status === s).length]));

  // ---------- views ----------
  function viewOverview() {
    const C = DATA.campaign, t = todayIso();
    const dayN = Math.round((isoDate(t) - isoDate(C.start)) / 864e5) + 1, total = Math.round((isoDate(C.end) - isoDate(C.start)) / 864e5) + 1;
    const inCampaign = dayN >= 1 && dayN <= total;
    const today = DATA.contacts.filter(c => c.dueIso === t);
    const todayActive = today.filter(c => READY(c.status));
    const briefToday = DATA.briefs.filter(b => b.date === t);
    const latest = DATA.briefs.at(-1);
    const r = DATA.recap; const ps = people();
    const contactsBy = s => ps.filter(p => p.status === s).length;
    const hero = `<section class="hero">
      <div><div class="eyebrow">${inCampaign ? `Day ${dayN} of ${total}` : dayN < 1 ? 'Starts soon' : 'Campaign complete'}</div>
        <h2>${esc(C.name)}</h2>
        <div class="meta"><span>${ICON.cal}${esc(dfmt(C.start, { month: 'short', day: 'numeric' }))}–${esc(dfmt(C.end, { month: 'short', day: 'numeric', year: 'numeric' }))}</span>
          <span>${ICON.users}${ps.length} contacts · ${DATA.contacts.length} planned touches</span>
          <span>${ICON.clock}Today: ${today.length} due · ${todayActive.length} ready to send</span></div>
        <div class="acct-chips">${C.accounts.map(a => `<span class="chip"><i>${esc(a.split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase())}</i>${esc(a)}</span>`).join('')}</div>
        <div class="actions">${(briefToday[0] || latest) ? `<a class="btn primary" href="#/doc/${esc((briefToday[0] || latest).id)}">${briefToday[0] ? "Open today's brief" : 'Open latest brief'}${ICON.arrow}</a>` : ''}<a class="btn ghost" href="#/accounts">Contact queue</a><span class="pill-stat">Prep only · Steve sends</span></div>
      </div>
      <div class="countdown day-ring"><div class="cd"><b>${String(Math.max(0, Math.min(total, dayN))).padStart(2, '0')}</b><small>day</small></div><div class="cd"><b>${String(Math.max(0, total - Math.max(0, dayN))).padStart(2, '0')}</b><small>left</small></div></div>
    </section>`;
    const stats = `<section class="stats">${[
      ['Draft Ready', r['Draft Ready'], `${contactsBy('Draft Ready')} contacts · touches`],
      ['On Hold', r['On Hold'], `${contactsBy('On Hold')} contacts · seller decision`],
      ['Sent confirmed', r['Sent Confirmed'], 'confirmed by Steve only'],
      ['Replies', r['Replied'], r['Replied'] ? 'confirmed replies' : 'none confirmed yet'],
    ].map(([k, v, s]) => `<div class="stat"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div><div class="s">${esc(s)}</div></div>`).join('')}</section>`;
    const sched = DATA.schedule.map(d => `<div class="day ${d.date === t ? 'today' : ''}"><div class="day-label">${esc(dayLabel(d.date))}<small>${esc(dfmt(d.date, { weekday: 'short', month: 'short', day: 'numeric' }))}</small></div>
      <div class="sched-items">${d.accounts.length ? d.accounts.map(a => { const href = a.brief ? `#/doc/${a.brief}` : `#/accounts/${encodeURIComponent(slug(a.account))}`;
        const sub = a.touches ? `${a.touches} touch${a.touches === 1 ? '' : 'es'} due · ${a.active} ready${a.brief ? ' · brief' : ''}` : a.queued ? 'Planned day · see contact queue' : 'Planned day · queue not built yet';
        return `<a class="sched-item" href="${esc(href)}"><div><b>${esc(a.account)}</b><small>${esc(sub)}</small></div>${a.active ? badge('Draft Ready') : a.touches ? badge(a.touches && !a.active && DATA.contacts.some(c => c.dueIso === d.date && c.account === a.account && c.status === 'On Hold') ? 'On Hold' : 'Research Needed') : '<span class="status todo">Planned</span>'}</a>`; }).join('')
        : `<div class="sched-empty">${d.recap ? 'Campaign performance summary and next-wave recommendations due.' : 'No touches scheduled yet.'}</div>`}</div></div>`).join('');
    const counts = DATA.statuses.map(s => `<span class="status ${CLS[s]}">${esc(s)} · ${r[s]}</span>`).join('');
    const needs = DATA.needs.slice(0, 5);
    return `${hero}${stats}
      <section class="panel"><div class="panel-head"><h2>Day-by-account schedule</h2><span class="muted">Planned days inferred from campaign order. Confirm with Steve.</span><div class="counts">${counts}</div></div><div class="sched">${sched}</div></section>
      <section class="panel"><div class="panel-head"><h2>Needs from Steve</h2><a class="btn sm" href="#/needs">All ${DATA.needs.length}${ICON.arrow}</a></div>${needsList(needs)}</section>
      <section class="panel"><div class="panel-head"><h2>Ground rules</h2></div><ul class="d-list d-body">${DATA.campaign.rules.map(x => `<li>${esc(x)}</li>`).join('')}</ul></section>`;
  }
  const slug = s => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  function needsList(list) {
    return list.length ? `<ol class="needs">${list.map((n, i) => `<li><span class="q-num">${i + 1}</span><div class="q-body"><a class="from" href="#/doc/${esc(n.docId)}">${esc(n.from)}</a><div class="q-text">${md(n.text)}${n.children?.length ? `<ul>${n.children.map(c => `<li>${md(c)}</li>`).join('')}</ul>` : ''}</div></div></li>`).join('')}</ol>` : emptyState('Nothing needed right now', 'Open items from the briefs appear here.');
  }
  function viewBriefs() {
    const docs = [...DATA.briefs.slice().reverse(), ...DATA.plans];
    return `<section class="panel"><div class="panel-head"><h2>Daily briefs &amp; plans</h2><span class="muted">${docs.length} document${docs.length === 1 ? '' : 's'}</span></div>
      <div class="cards">${docs.length ? docs.map(d => `<a class="card doc-card" href="#/doc/${esc(d.id)}"><div class="time"><b>${d.date ? esc(dfmt(d.date, { month: 'short', day: 'numeric' })) : 'Plan'}</b><small>${d.date ? esc(dayLabel(d.date)) : 'relationship'}</small></div>
        <div><div class="title-row"><span class="acct">${esc(d.account)}</span><h3>${esc(d.kind === 'brief' ? 'Daily execution brief' : 'Relationship plan')}</h3></div><p class="objective">${esc(d.sections.map(s => s.heading).filter(Boolean).slice(0, 5).join(' · '))}</p></div>
        <div class="side"><span class="btn primary sm">Open${ICON.arrow}</span></div></a>`).join('') : emptyState('No briefs yet', 'Briefs appear after the next morning refresh.')}</div></section>`;
  }
  function viewDoc(id) {
    const d = [...DATA.briefs, ...DATA.plans].find(x => x.id === id);
    if (!d) return `<nav class="crumbs"><a href="#/briefs">${ICON.back}All briefs</a></nav><div class="panel">${emptyState('Document not found', 'This link may be from an older refresh.')}</div>`;
    const side = d.sections.filter(s => /recap|blocker|needs|missing/i.test(s.heading));
    const main = d.sections.filter(s => !side.includes(s));
    return `<nav class="crumbs no-print"><a href="#/briefs">${ICON.back}All briefs</a></nav>
      <header class="d-hero hero"><div><div class="eyebrow">${d.kind === 'brief' ? 'Daily execution brief' : 'Relationship plan'} <span class="acct on-hero">${esc(d.account)}</span></div>
        <h1>${esc(d.title)}</h1><div class="meta">${d.date ? `<span>${ICON.cal}${esc(dfmt(d.date, { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }))}</span>` : ''}<span>${ICON.doc}${d.sections.length} sections</span></div>
        <div class="actions no-print"><button class="btn ghost" type="button" data-action="print">${ICON.print}Print</button></div></div>
        <div class="d-hero-side">${d.date ? `<span class="status ${d.date === todayIso() ? 'draft' : 'todo'}">${esc(dayLabel(d.date))}</span>` : ''}</div></header>
      <div class="d-grid"><div class="d-main">${d.header.length ? section('', renderBlocks(d.header)) : ''}${main.map(s => section(s.heading, renderBlocks(s.blocks))).join('')}</div>
        <aside class="d-side">${side.map(s => section(s.heading, renderBlocks(s.blocks))).join('') || section('At a glance', '<p class="fine-print">Read-only mirror of the brief file. Changes appear after the next refresh.</p>')}</aside></div>`;
  }
  let FILTER = 'all';
  function viewAccounts(only) {
    const accs = accounts().filter(a => !only || slug(a.name) === only);
    const filt = p => FILTER === 'all' || p.status === FILTER;
    const segs = ['all', ...DATA.statuses].map(s => `<button class="seg-btn ${FILTER === s ? 'active' : ''}" data-filter="${esc(s)}">${s === 'all' ? 'All' : esc(s)}</button>`).join('');
    return `${only ? `<nav class="crumbs"><a href="#/accounts">${ICON.back}All accounts</a></nav>` : ''}<div class="seg filters" role="tablist">${segs}</div>
      ${accs.map(a => { const ps = a.people.filter(filt); const cnt = statCounts(a.people.map(p => ({ status: p.status })));
        return `<section class="panel acct-panel"><div class="panel-head"><div class="acct-head"><h2>${esc(a.name)}</h2><span class="muted">${a.people.length} contact${a.people.length === 1 ? '' : 's'}</span></div>
          <div class="counts">${DATA.statuses.filter(s => cnt[s]).map(s => `<span class="status ${CLS[s]}">${esc(s)} · ${cnt[s]}</span>`).join('')}</div></div>
          <div class="cards">${ps.length ? ps.sort((x, y) => RANK.indexOf(x.status) - RANK.indexOf(y.status)).map(p => `<a class="card c-card" href="#/contact/${esc(p.rid)}">
            <div><div class="title-row"><h3>${esc(p.name)}</h3></div><p class="role">${md(p.role)}</p>
              <div class="c-meta"><span>${ICON.clock}${esc(p.next.due || '—')}</span><span>${ICON.notes}${p.rows.length} touch${p.rows.length === 1 ? '' : 'es'} · ${esc(p.next.draft || '')}</span><span>${ICON.flag}${esc(p.next.nextAction || '')}</span></div></div>
            <div class="side">${p.overdue ? '<span class="status urgent">Overdue</span>' : ''}${badge(p.status)}<span class="btn primary sm">Open${ICON.arrow}</span></div></a>`).join('')
            : `<div class="sched-empty">${a.people.length ? 'No contacts match this filter.' : 'Queue not built yet for this account.'}</div>`}</div></section>`; }).join('')}`;
  }
  function viewContact(id) {
    const p = people().find(x => x.rid === id);
    if (!p) return `<nav class="crumbs"><a href="#/accounts">${ICON.back}Contact queue</a></nav><div class="panel">${emptyState('Contact not found', 'This link may be from an older refresh.')}</div>`;
    const f = p.rows[0];
    const kv = rows => `<dl class="kv-grid">${rows.filter(([, v]) => v).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${md(v)}</dd>`).join('')}</dl>`;
    const drafts = p.rows.map(r => { const text = r.connectionNote || r.followup;
      return `<div class="draft"><div class="draft-head"><h3>${esc(r.action)}</h3>${badgeFor(r)}<span class="chars">${esc(r.draft)}${r.actionCode === 'CONNECT' && text ? ` · ${text.replace(/^PROVISIONAL — /, '').length} chars` : ''}</span></div>
        ${text ? `<blockquote>${md(text)}</blockquote>` : '<p class="muted">No draft text.</p>'}
        ${kv([['Key', r.key], ['Due', r.due], ['Next action', r.nextAction], ['Status (raw)', r.statusRaw]])}</div>`; }).join('');
    return `<nav class="crumbs no-print"><a href="#/accounts">${ICON.back}Contact queue</a></nav>
      <header class="d-hero hero"><div><div class="eyebrow">Contact <span class="acct on-hero">${esc(p.account)}</span></div><h1>${esc(p.name)}</h1>
        <div class="meta"><span>${ICON.users}${md(p.role)}</span></div>
        <div class="actions no-print"><button class="btn ghost" type="button" data-action="print">${ICON.print}Print</button><span class="pill-stat">Steve sends manually</span></div></div>
        <div class="d-hero-side">${p.overdue ? '<span class="status urgent">Overdue</span>' : ''}${badge(p.status)}</div></header>
      <div class="d-grid"><div class="d-main">
        ${section('Drafts', drafts, `${p.rows.length}`)}
        ${section('Signal & evidence', kv([['Signal', f.signal], ['Sources', f.signalSource]]))}
        ${section('Opportunity hypothesis', `<p>${md(f.hypothesis)}</p>`)}
      </div><aside class="d-side">
        ${section('Relationship', kv([['Role source', f.roleSource], ['Verified', f.roleVerified], ['Relationship', f.relationship], ['LinkedIn ref', f.linkedin], ['Warm intro', f.warmIntro], ['Latest touch', f.latestTouch], ['Last interaction', f.lastInteraction]]))}
        ${section('Checks', kv([['Duplicate / opt-out', f.dupCheck], ['Recommended', f.recommended], ['Source', f.source]]))}
      </aside></div>`;
  }
  function viewNeeds() { return `<section class="panel"><div class="panel-head"><h2>Needs from Steve</h2><span class="muted">${DATA.needs.length} open item${DATA.needs.length === 1 ? '' : 's'}</span></div>${needsList(DATA.needs)}</section>`; }

  // ---------- router ----------
  function route() {
    if (!DATA) return;
    const h = location.hash || '#/'; let m, html, nav = 'overview';
    if ((m = h.match(/^#\/doc\/([A-Za-z0-9_-]+)/))) { html = viewDoc(m[1]); nav = 'briefs'; }
    else if (h.startsWith('#/briefs')) { html = viewBriefs(); nav = 'briefs'; }
    else if ((m = h.match(/^#\/contact\/([A-Za-z0-9_-]+)/))) { html = viewContact(m[1]); nav = 'accounts'; }
    else if ((m = h.match(/^#\/accounts(?:\/([a-z0-9-]+))?/))) { html = viewAccounts(m[1]); nav = 'accounts'; }
    else if (h.startsWith('#/needs')) { html = viewNeeds(); nav = 'needs'; }
    else html = viewOverview();
    const v = $('#view'); v.className = 'content' + (/doc|contact/.test(h) ? ' detail' : ''); v.innerHTML = html;
    document.querySelectorAll('#nav [data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === nav));
    $('#needs-count').textContent = DATA.needs.length || '';
    const gen = new Date(DATA.generatedAt);
    $('#subtitle').textContent = `Updated ${fmt(gen, { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })} ${tzAbbr(gen)}`;
    $('#foot').textContent = `Prep only · Steve sends every touch · All dates Central (${tzAbbr(new Date())}) · Encrypted client-side, AES-256-GCM`;
    $('#example-banner').hidden = !DATA.example;
  }
  let LAST = '';
  window.addEventListener('hashchange', () => { route(); if (location.hash !== LAST) window.scrollTo(0, 0); LAST = location.hash; });
  document.addEventListener('click', e => {
    if (e.target.closest('[data-action="print"]')) window.print();
    const f = e.target.closest('[data-filter]'); if (f) { FILTER = f.dataset.filter; route(); }
  });

  // ---------- lock / unlock ----------
  const SS = 'lbd-pass';
  async function unlock(pass, remember) {
    DATA = await decrypt(await fetchBlob(), pass);
    if (remember) sessionStorage.setItem(SS, pass);
    $('#lock').hidden = true; $('#app').hidden = false; $('#pass').value = '';
    route();
  }
  function lock() { DATA = null; sessionStorage.removeItem(SS); $('#view').innerHTML = ''; $('#app').hidden = true; $('#lock').hidden = false; $('#pass').focus(); }
  $('#unlock-form').addEventListener('submit', async e => {
    e.preventDefault(); const btn = $('#unlock-btn'), err = $('#lock-error');
    err.hidden = true; btn.disabled = true; btn.textContent = 'Unlocking…';
    try { await unlock($('#pass').value, $('#remember').checked); }
    catch (x) { err.textContent = x.name === 'OperationError' ? 'Incorrect passphrase. Try again.' : (x.message || 'Unable to unlock.'); err.hidden = false; }
    finally { btn.disabled = false; btn.textContent = 'Unlock'; }
  });
  $('#lock-btn').addEventListener('click', lock);
  const saved = sessionStorage.getItem(SS);
  if (saved) unlock(saved, true).catch(() => sessionStorage.removeItem(SS));
})();
