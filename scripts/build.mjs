#!/usr/bin/env node
// Build the encrypted LinkedIn Blitz dataset for the dashboard.
// Same scheme as the meeting-prep dashboard: AES-256-GCM, key = PBKDF2-SHA256(DASHBOARD_PASSPHRASE, random 16-byte salt,
// 600k iterations), random 12-byte IV, fresh on every build. Plaintext never touches the repo.
//
// Source dir: $BLITZ_DIR (default /workspace/linkedin-blitz): campaign.json, activity_log.csv, YYYY-MM-DD_<Account>_brief.md, *_relationship_plan.md
// Emails and phone numbers are stripped from every string before encryption.
// Flags: --dry-run (counts only, no write) · --example (labeled EXAMPLE data into example/, gitignored)
import { webcrypto as crypto, createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = process.env.BLITZ_DIR || '/workspace/linkedin-blitz';
const ITERATIONS = 600_000;
const args = new Set(process.argv.slice(2));
const DRY = args.has('--dry-run'), EXAMPLE = args.has('--example');

// Campaign config (accounts, calendar, rules) lives with the private source files, not in this repo.
const CAMPAIGN = { name: 'LinkedIn Blitz', plan: {}, rules: [], accounts: [], ...JSON.parse(await fs.readFile(path.join(SRC, 'campaign.json'), 'utf8').catch(() => '{}')) };
const STATUSES = ['Research Needed', 'Draft Ready', 'Approved', 'Sent Confirmed', 'Replied', 'Next Action', 'On Hold'];

// ---------- PII scrub ----------
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g;
const MAILTO = /mailto:[^\s)\]]*/gi;
const PHONE = /(?<![\w/=.-])(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)/g;
let stripped = { email: 0, phone: 0 };
const scrub = s => typeof s !== 'string' ? s : s
  .replace(MAILTO, () => (stripped.email++, '[removed]'))
  .replace(EMAIL, () => (stripped.email++, '[removed]'))
  .replace(PHONE, () => (stripped.phone++, '[removed]'));
const deepScrub = v => Array.isArray(v) ? v.map(deepScrub) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, deepScrub(x)])) : scrub(v);

// ---------- helpers ----------
const rid = (ns, s) => createHash('sha256').update(`lbd-${ns}-v1:${s}`).digest('base64url').slice(0, 12);
function parseCSV(text) {
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(f); rows.push(row); row = []; f = ''; }
    else f += c;
  }
  if (f || row.length) { row.push(f); rows.push(row); }
  const [h, ...body] = rows.filter(r => r.some(x => x.trim()));
  return body.map(r => Object.fromEntries(h.map((k, i) => [k.replace(/^\ufeff/, ''), (r[i] ?? '').trim()])));
}
export function normStatus(s) {
  const t = (s || '').toLowerCase();
  if (t.startsWith('on hold')) return 'On Hold';
  return STATUSES.find(x => t.startsWith(x.toLowerCase())) || (s ? 'Next Action' : 'Research Needed');
}
const isoDue = s => (s.match(/^\s*(20\d\d-\d\d-\d\d)\b/) || [])[1] || null; // estimates ("est. …") are not due dates
const ACTION = { CONNECT: 'Connection note', AFTERACCEPT: 'After-accept message', VALUEADD: 'Value-add follow-up' };

// Markdown -> blocks (headings, lists w/ nesting, quotes, pipe tables, paragraphs)
export function mdBlocks(md) {
  const root = []; const stack = [{ indent: -1, children: root }];
  const lines = md.replace(/\r/g, '').split('\n');
  const push = (b, indent) => { while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop(); stack[stack.length - 1].children.push(b); return b; };
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]; if (!l.trim()) continue;
    const indent = (l.match(/^[ \t]*/)[0].replace(/\t/g, '  ')).length;
    let m;
    if (/^\s*\|/.test(l)) {
      const rows = []; while (i < lines.length && /^\s*\|/.test(lines[i])) { if (!/^\s*\|[\s:|-]+\|?\s*$/.test(lines[i])) rows.push(lines[i].trim().replace(/^\||\|$/g, '').split(/(?<!\\)\|/).map(c => c.trim())); i++; }
      i--; push({ type: 'table', header: true, rows }, indent); continue;
    }
    if ((m = l.match(/^(#{1,4})\s+(.*)$/))) { stack.length = 1; root.push({ type: 'heading', level: m[1].length, text: m[2].trim() }); continue; }
    if ((m = l.match(/^\s*[-*]\s+(.*)$/))) { const b = push({ type: 'bullet', text: m[1], children: [] }, indent); stack.push({ indent, children: b.children }); continue; }
    if ((m = l.match(/^\s*\d+\.\s+(.*)$/))) { const b = push({ type: 'numbered', text: m[1], children: [] }, indent); stack.push({ indent, children: b.children }); continue; }
    if ((m = l.match(/^\s*>\s?(.*)$/))) { push({ type: 'quote', text: m[1] }, indent); continue; }
    push({ type: 'paragraph', text: l.trim() }, indent);
  }
  return root;
}
// Group blocks into sections by H2 (H1 is the doc title, H3+ stay inside sections)
function sectionize(blocks) {
  const secs = []; let cur = { heading: '', blocks: [] }; let title = '';
  for (const b of blocks) {
    if (b.type === 'heading' && b.level === 1) { title = title || b.text; continue; }
    if (b.type === 'heading' && b.level === 2) { if (cur.heading || cur.blocks.length) secs.push(cur); cur = { heading: b.text, blocks: [] }; continue; }
    cur.blocks.push(b);
  }
  if (cur.heading || cur.blocks.length) secs.push(cur);
  return { title, sections: secs };
}
const textOf = bs => bs.map(b => [b.text, ...(b.children ? [textOf(b.children)] : [])].filter(Boolean).join(' ')).join(' ');

// ---------- read sources ----------
async function readSources() {
  const files = await fs.readdir(SRC);
  const log = parseCSV(await fs.readFile(path.join(SRC, 'activity_log.csv'), 'utf8'));
  const contacts = log.map(r => {
    const [acctCode, first, date, act] = r.key.split('-');
    return {
      id: rid('row', r.key), key: r.key, account: r.account, contact: r.contact, role: r.role, roleSource: r.role_source,
      roleVerified: r.role_verified_date, relationship: r.relationship_status, linkedin: r.linkedin_ref, warmIntro: r.warm_intro_candidate,
      latestTouch: r.latest_confirmed_touch, signal: r.signal, signalSource: r.signal_source, hypothesis: r.hypothesis,
      connectionNote: r.connection_note, followup: r.followup_message, recommended: r.recommended_action, dupCheck: r.dup_optout_check,
      draft: r.draft_version, lastInteraction: r.last_confirmed_interaction, nextAction: r.next_action, due: r.due_date, dueIso: isoDue(r.due_date),
      source: r.source, statusRaw: r.confirmation_status, status: normStatus(r.confirmation_status),
      action: ACTION[act] || act || '', actionCode: act || '', person: first ? first[0] + first.slice(1).toLowerCase() : '', personKey: `${acctCode}-${first}`,
    };
  });
  const briefs = [];
  for (const f of files.filter(f => /^\d{4}-\d{2}-\d{2}_.+_brief\.md$/.test(f)).sort()) {
    const md = await fs.readFile(path.join(SRC, f), 'utf8');
    const [, date, acct] = f.match(/^(\d{4}-\d{2}-\d{2})_(.+)_brief\.md$/);
    const { title, sections } = sectionize(mdBlocks(md));
    const header = sections.length && !sections[0].heading ? sections.shift().blocks : [];
    briefs.push({ id: rid('brief', f), kind: 'brief', date, account: acct.replace(/_/g, ' '), title: title || 'Daily execution brief', header, sections });
  }
  const plans = [];
  for (const f of files.filter(f => /_relationship_plan\.md$/.test(f)).sort()) {
    const md = await fs.readFile(path.join(SRC, f), 'utf8');
    const { title, sections } = sectionize(mdBlocks(md));
    const header = sections.length && !sections[0].heading ? sections.shift().blocks : [];
    plans.push({ id: rid('plan', f), kind: 'plan', date: null, account: f.split('_')[0], title: title || 'Relationship plan', header, sections });
  }
  // Needs from Steve: blocker sections of the latest brief + every plan
  const needs = [];
  const take = (doc, label) => { for (const s of doc.sections.filter(s => /blocker|needs from steve/i.test(s.heading))) for (const b of s.blocks) if (['numbered', 'bullet'].includes(b.type)) needs.push({ from: label, docId: doc.id, text: b.text, children: (b.children || []).map(c => c.text) }); };
  const latest = briefs.at(-1); if (latest) take(latest, `${latest.account} brief · ${latest.date}`);
  for (const p of plans) take(p, `${p.account} plan`);
  return { contacts, briefs, plans, needs };
}

// ---------- schedule + recap ----------
function buildSchedule(contacts, briefs) {
  const days = []; const s = new Date(CAMPAIGN.start + 'T12:00:00Z'), e = new Date(CAMPAIGN.end + 'T12:00:00Z');
  for (let d = new Date(s); d <= e; d.setUTCDate(d.getUTCDate() + 1)) {
    const iso = d.toISOString().slice(0, 10);
    const touches = contacts.filter(c => c.dueIso === iso);
    const planned = CAMPAIGN.plan[iso];
    const accts = [...new Set([...(planned ? [planned] : []), ...touches.map(c => c.account), ...briefs.filter(b => b.date === iso).map(b => b.account)])];
    days.push({ date: iso, accounts: accts.map(a => ({ account: a, touches: touches.filter(t => t.account === a).length,
      active: touches.filter(t => t.account === a && ['Draft Ready', 'Approved', 'Next Action'].includes(t.status)).length,
      brief: briefs.find(b => b.date === iso && b.account === a)?.id || null, planned: a === planned, queued: contacts.some(c => c.account === a) })), recap: iso === CAMPAIGN.end });
  }
  return days;
}
const recap = cs => Object.fromEntries(STATUSES.map(s => [s, cs.filter(c => c.status === s).length]));

// ---------- crypto (identical to meeting-prep) ----------
const b64 = u8 => Buffer.from(u8).toString('base64');
async function encrypt(obj, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj))));
  return { v: 1, alg: 'AES-256-GCM', kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
}

function exampleData() {
  const mk = (i, acct, person, status, due) => ({ id: rid('ex', i), key: `EX-${person.toUpperCase()}-${due.replace(/-/g, '')}-CONNECT`, account: `EXAMPLE ${acct}`, contact: `Example ${person}`, role: 'EXAMPLE role', roleSource: 'EXAMPLE source', roleVerified: due, relationship: 'EXAMPLE', linkedin: '—', warmIntro: 'EXAMPLE', latestTouch: 'None', signal: 'EXAMPLE signal', signalSource: 'https://example.com/', hypothesis: 'HYPOTHESIS: EXAMPLE', connectionNote: 'EXAMPLE connection note.', followup: '', recommended: 'EXAMPLE', dupCheck: 'EXAMPLE', draft: 'v1', lastInteraction: 'None', nextAction: 'EXAMPLE', due, dueIso: due, source: 'example', statusRaw: status, status, action: 'Connection note', actionCode: 'CONNECT', person, personKey: `EX-${person}` });
  const contacts = [mk(1, 'Acme', 'Ada', 'Draft Ready', '2026-10-20'), mk(2, 'Acme', 'Ben', 'Research Needed', '2026-10-20'), mk(3, 'Globex', 'Cy', 'On Hold', '2026-10-23'), mk(4, 'Globex', 'Di', 'Approved', '2026-10-23')];
  const briefs = [{ id: rid('ex', 'b'), kind: 'brief', date: '2026-10-20', account: 'EXAMPLE Acme', title: 'EXAMPLE brief', header: [{ type: 'paragraph', text: '**EXAMPLE DATA** for design preview.' }], sections: [{ heading: 'Ranked queue', blocks: [{ type: 'table', header: true, rows: [['Rank', 'Contact', 'Why'], ['1', 'Example Ada', 'EXAMPLE reason']] }] }] }];
  return { contacts, briefs, plans: [], needs: [{ from: 'EXAMPLE', docId: briefs[0].id, text: 'EXAMPLE need', children: [] }] };
}

async function main() {
  const pass = process.env.DASHBOARD_PASSPHRASE;
  if (!pass && !DRY) { console.error('DASHBOARD_PASSPHRASE is not set.'); process.exit(1); }
  if (pass && pass.length < 12) console.warn('Warning: passphrase shorter than 12 characters.');
  const src = EXAMPLE ? exampleData() : await readSources();
  let payload = { generatedAt: new Date().toISOString(), example: EXAMPLE, campaign: CAMPAIGN, statuses: STATUSES, ...src,
    schedule: buildSchedule(src.contacts, src.briefs), recap: recap(src.contacts) };
  payload = deepScrub(payload);
  console.log(`rows: ${src.contacts.length} · contacts: ${new Set(src.contacts.map(c => c.personKey)).size} · briefs: ${src.briefs.length} · plans: ${src.plans.length} · needs: ${src.needs.length} · stripped emails: ${stripped.email}, phones: ${stripped.phone}`);
  if (DRY) return;
  const outDir = EXAMPLE ? path.join(ROOT, 'example') : path.join(ROOT, 'docs');
  await fs.mkdir(outDir, { recursive: true });
  await fs.writeFile(path.join(outDir, 'data.enc.json'), JSON.stringify(await encrypt(payload, pass)) + '\n');
  if (args.has('--plain-check')) await fs.writeFile(path.join(ROOT, 'example', 'last.plain.json'), JSON.stringify(payload, null, 1)); // gitignored, local QA only
  console.log(`wrote ${path.relative(ROOT, path.join(outDir, 'data.enc.json'))}`);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(e => { console.error(e.message); process.exit(1); });
