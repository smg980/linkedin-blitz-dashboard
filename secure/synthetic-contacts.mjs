// Four fictional contacts. This is the only dataset the emulator ingestion tool can write.
// Real campaign ingestion is a separate approved step and has no entry point here.
function row(id, account, person, status, due) {
  return {
    id: `EX-${id}`,
    key: `EX-${person.toUpperCase()}-${due.replace(/-/g, '')}-CONNECT`,
    account: `EXAMPLE ${account}`,
    contact: `Example ${person}`,
    role: 'EXAMPLE role',
    roleSource: 'EXAMPLE source',
    relationship: 'EXAMPLE',
    linkedin: '—',
    signal: 'EXAMPLE signal',
    hypothesis: 'HYPOTHESIS: EXAMPLE',
    connectionNote: 'EXAMPLE connection note.',
    followup: '',
    recommended: 'EXAMPLE',
    dupCheck: 'EXAMPLE',
    draft: 'v1',
    nextAction: 'EXAMPLE',
    due,
    dueIso: due,
    source: 'example',
    status,
    action: 'Connection note',
    actionCode: 'CONNECT',
    person,
  };
}

export function syntheticPayload(generatedAt = '2026-10-20T12:00:00.000Z') {
  const contacts = [
    row(1, 'Acme', 'Ada', 'Draft Ready', '2026-10-20'),
    row(2, 'Acme', 'Ben', 'Research Needed', '2026-10-20'),
    row(3, 'Globex', 'Cy', 'On Hold', '2026-10-23'),
    row(4, 'Globex', 'Di', 'Approved', '2026-10-23'),
  ];
  return {
    generatedAt,
    example: true,
    campaign: {
      name: 'EXAMPLE LinkedIn Blitz',
      start: '2026-10-20',
      end: '2026-10-23',
      plan: {},
      rules: ['EXAMPLE DATA ONLY — do not send'],
      accounts: ['EXAMPLE Acme', 'EXAMPLE Globex'],
    },
    statuses: ['Research Needed', 'Draft Ready', 'Approved', 'Sent Confirmed', 'Replied', 'Next Action', 'On Hold'],
    contacts,
    briefs: [],
    plans: [],
    needs: [],
    schedule: [],
    recap: {},
  };
}
