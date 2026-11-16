const STATUS_CLASS = {
  'Research Needed': 'todo',
  'Draft Ready': 'draft',
  Approved: 'approved',
  'Sent Confirmed': 'ready',
  Replied: 'ready',
  'Next Action': 'next',
  'On Hold': 'hold',
};

function el(doc, tag, className, text) {
  const node = doc.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

export function renderPrivateView(root, data) {
  const doc = root.ownerDocument;
  const campaign = data?.campaign || {};
  const contacts = Array.isArray(data?.contacts) ? data.contacts : [];
  const hero = el(doc, 'section', 'hero');
  const copy = el(doc, 'div');
  copy.append(
    el(doc, 'div', 'eyebrow', 'Read only'),
    el(doc, 'h2', '', campaign.name || 'LinkedIn Blitz'),
  );
  const meta = el(doc, 'div', 'meta');
  meta.append(el(doc, 'span', '', `${campaign.start || '—'} – ${campaign.end || '—'}`));
  meta.append(el(doc, 'span', '', `${contacts.length} contacts`));
  copy.append(meta);
  const note = el(doc, 'p', 'fine', 'Prep only. This page does not send LinkedIn messages or change a status.');
  copy.append(note);
  hero.append(copy);
  root.append(hero);

  const groups = new Map();
  for (const contact of contacts) {
    const account = String(contact?.account || 'Account');
    if (!groups.has(account)) groups.set(account, []);
    groups.get(account).push(contact);
  }
  if (!groups.size) {
    const empty = el(doc, 'section', 'panel');
    empty.append(el(doc, 'p', 'muted', 'No contacts in this snapshot.'));
    root.append(empty);
    return;
  }
  for (const [account, people] of groups) {
    const panel = el(doc, 'section', 'panel');
    const head = el(doc, 'div', 'panel-head');
    head.append(el(doc, 'h2', '', account));
    head.append(el(doc, 'span', 'muted', `${people.length} contact${people.length === 1 ? '' : 's'}`));
    const cards = el(doc, 'div', 'cards');
    for (const person of people) {
      const card = el(doc, 'article', 'card');
      const body = el(doc, 'div');
      body.append(el(doc, 'h3', '', person.contact || 'Contact'));
      if (person.role) body.append(el(doc, 'p', 'role', person.role));
      const badge = el(doc, 'span', `status ${STATUS_CLASS[person.status] || 'todo'}`, person.status || 'Unknown');
      body.append(badge);
      if (person.connectionNote) body.append(el(doc, 'p', '', person.connectionNote));
      card.append(body);
      cards.append(card);
    }
    panel.append(head, cards);
    root.append(panel);
  }
}
