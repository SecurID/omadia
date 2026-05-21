import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import {
  odooMany2OnePiiField,
  odooSearchReadPiiFields,
} from '@omadia/plugin-api';
import { applyStableIdTokenization } from '@omadia/plugin-privacy-guard/dist/stableIdTokenization.js';
import { createTokenizeMap } from '@omadia/plugin-privacy-guard/dist/tokenizeMap.js';

// ---------------------------------------------------------------------------
// Privacy-Shield v3 (stable-id tokenization, slice 1) — tool-aware PII
// pre-pass. Walks a tool's structured result against operator-declared
// `piiFields` annotations and rewrites annotated leaves into stable
// tokens BEFORE the NER detectors run. Replaces partial-name leaks
// ("«PERSON_5» Vomberg") with whole-field tokenization, and avoids
// the row-doubling failure mode where the same employee yields two
// different counter tokens within the same tool call.
// ---------------------------------------------------------------------------

describe('applyStableIdTokenization · slice 1', () => {
  it('rewrites a top-level field by path', () => {
    const map = createTokenizeMap();
    const raw = { employee_id: 162, name: 'Marvin Vomberg', dept: 'Backend' };
    const result = applyStableIdTokenization(
      raw,
      [{ path: 'name', idPath: 'employee_id', type: 'PERSON' }],
      map,
    );
    assert.equal(result.replaced, 1);
    assert.equal(result.skipped, 0);
    const v = result.value as Record<string, unknown>;
    assert.ok(typeof v.name === 'string');
    assert.match(v.name as string, /^«PERSON_\d+»$/);
    assert.equal(v.dept, 'Backend'); // unrelated fields untouched
    // Restoration via the same map yields the original string.
    assert.equal(map.resolve(v.name as string), 'Marvin Vomberg');
  });

  it('rewrites an array-spread (HR-Urlaubsranking shape)', () => {
    const map = createTokenizeMap();
    const raw = {
      employees: [
        { employee_id: 162, name: 'Marvin Vomberg', days: 17 },
        { employee_id: 103, name: 'Dennis Zille', days: 16.69 },
        { employee_id: 198, name: 'Sophie Neumann', days: 13 },
      ],
    };
    const result = applyStableIdTokenization(
      raw,
      [
        {
          path: 'employees[].name',
          idPath: 'employees[].employee_id',
          type: 'PERSON',
        },
      ],
      map,
    );
    assert.equal(result.replaced, 3);
    assert.equal(result.skipped, 0);
    const employees = (result.value as { employees: Array<Record<string, unknown>> })
      .employees;
    for (const emp of employees) {
      assert.match(emp.name as string, /^«PERSON_\d+»$/);
    }
    // Numeric fields and ids stay untouched.
    assert.equal(employees[0]?.employee_id, 162);
    assert.equal(employees[0]?.days, 17);
  });

  it('keys tokens by entity id: same employee across rows yields one token', () => {
    // Slice 1.5 — dedup is keyed by the id at `idPath`, not the value.
    // Two leave bookings by the SAME employee (employee_id 162) get
    // the SAME token even though their booking ids differ.
    const map = createTokenizeMap();
    const raw = {
      bookings: [
        { booking_id: 1257, employee_id: 162, name: 'Marvin Vomberg' },
        { booking_id: 1085, employee_id: 162, name: 'Marvin Vomberg' },
        { booking_id: 1077, employee_id: 103, name: 'Dennis Zille' },
      ],
    };
    const result = applyStableIdTokenization(
      raw,
      [
        {
          path: 'bookings[].name',
          idPath: 'bookings[].employee_id',
          type: 'PERSON',
        },
      ],
      map,
    );
    assert.equal(result.replaced, 3);
    const bookings = (result.value as { bookings: Array<Record<string, unknown>> })
      .bookings;
    assert.equal(bookings[0]?.name, bookings[1]?.name); // same employee id
    assert.notEqual(bookings[0]?.name, bookings[2]?.name); // different employee
  });

  it('disambiguates homonyms: same name + different id yields distinct tokens', () => {
    // The exact failure the slice-1 value-dedup would have caused in a
    // ranking: two genuinely different employees who share a name.
    const map = createTokenizeMap();
    const raw = {
      employees: [
        { employee_id: 12, name: 'Thomas Müller' },
        { employee_id: 88, name: 'Thomas Müller' },
      ],
    };
    const result = applyStableIdTokenization(
      raw,
      [
        {
          path: 'employees[].name',
          idPath: 'employees[].employee_id',
          type: 'PERSON',
        },
      ],
      map,
    );
    assert.equal(result.replaced, 2);
    const employees = (result.value as { employees: Array<Record<string, unknown>> })
      .employees;
    // Distinct ids → distinct tokens, even though the name is identical.
    assert.notEqual(employees[0]?.name, employees[1]?.name);
    // Both tokens still resolve to the real name.
    assert.equal(map.resolve(employees[0]?.name as string), 'Thomas Müller');
    assert.equal(map.resolve(employees[1]?.name as string), 'Thomas Müller');
  });

  it('skips leaves that are missing, null, undefined, or non-string', () => {
    const map = createTokenizeMap();
    const raw = {
      items: [
        { id: 1, name: 'Real Name' },
        { id: 2, name: null }, // null leaf
        { id: 3 }, // missing field
        { id: 4, name: 42 }, // wrong type
        { id: 5, name: '' }, // empty string
        { id: 6, name: 'Other Name' },
      ],
    };
    const result = applyStableIdTokenization(
      raw,
      [{ path: 'items[].name', idPath: 'items[].id', type: 'PERSON' }],
      map,
    );
    // Only the two real string leaves get tokenised.
    assert.equal(result.replaced, 2);
    const items = (result.value as { items: Array<Record<string, unknown>> }).items;
    assert.match(items[0]?.name as string, /^«PERSON_\d+»$/);
    assert.equal(items[1]?.name, null);
    assert.equal(items[2]?.name, undefined);
    assert.equal(items[3]?.name, 42);
    assert.equal(items[4]?.name, '');
    assert.match(items[5]?.name as string, /^«PERSON_\d+»$/);
  });

  it('skips the annotation entirely when path/idPath shapes disagree', () => {
    const map = createTokenizeMap();
    const raw = {
      employees: [{ employee_id: 1, name: 'Anna' }],
      meta: { batch_id: 42 },
    };
    // path goes through one `[]`, idPath through none — must reject.
    const result = applyStableIdTokenization(
      raw,
      [{ path: 'employees[].name', idPath: 'meta.batch_id', type: 'PERSON' }],
      map,
    );
    assert.equal(result.replaced, 0);
    assert.equal(result.skipped, 1);
    // The data is unchanged on shape-mismatch.
    const employees = (result.value as { employees: Array<Record<string, unknown>> })
      .employees;
    assert.equal(employees[0]?.name, 'Anna');
  });

  it('skips when parallel arrays have different lengths', () => {
    const map = createTokenizeMap();
    // Build a shape where `employees[]` resolves to 3 leaves but
    // `partners[]` resolves to 2 — the walker cannot zip them.
    const raw = {
      employees: [
        { name: 'Anna' },
        { name: 'Beate' },
        { name: 'Clara' },
      ],
      partners: [{ id: 1 }, { id: 2 }],
    };
    const result = applyStableIdTokenization(
      raw,
      [{ path: 'employees[].name', idPath: 'partners[].id', type: 'PERSON' }],
      map,
    );
    assert.equal(result.replaced, 0);
    assert.equal(result.skipped, 1);
  });

  it('returns the input untouched when annotations are empty', () => {
    const map = createTokenizeMap();
    const raw = { name: 'Alice' };
    const result = applyStableIdTokenization(raw, [], map);
    assert.equal(result.replaced, 0);
    assert.equal(result.skipped, 0);
    assert.strictEqual(result.value, raw); // same reference — no clone
  });

  it('returns input untouched when raw is not a plain object', () => {
    const map = createTokenizeMap();
    const result = applyStableIdTokenization(
      'just a string',
      [{ path: 'name', idPath: 'id', type: 'PERSON' }],
      map,
    );
    assert.equal(result.replaced, 0);
    assert.equal(result.skipped, 0);
    assert.equal(result.value, 'just a string');
  });

  it('does not mutate the caller-supplied object', () => {
    const map = createTokenizeMap();
    const raw = {
      employees: [{ employee_id: 162, name: 'Marvin Vomberg' }],
    };
    const before = JSON.stringify(raw);
    applyStableIdTokenization(
      raw,
      [
        {
          path: 'employees[].name',
          idPath: 'employees[].employee_id',
          type: 'PERSON',
        },
      ],
      map,
    );
    assert.equal(JSON.stringify(raw), before);
  });

  it('defaults type to PERSON when omitted', () => {
    const map = createTokenizeMap();
    const raw = { name: 'Anna Müller', id: 1 };
    const result = applyStableIdTokenization(
      raw,
      [{ path: 'name', idPath: 'id' }],
      map,
    );
    assert.equal(result.replaced, 1);
    const v = result.value as Record<string, unknown>;
    assert.match(v.name as string, /^«PERSON_\d+»$/);
  });

  it('handles non-PERSON types (EMAIL)', () => {
    const map = createTokenizeMap();
    const raw = { user_id: 7, email: 'anna@example.com' };
    const result = applyStableIdTokenization(
      raw,
      [{ path: 'email', idPath: 'user_id', type: 'EMAIL' }],
      map,
    );
    assert.equal(result.replaced, 1);
    const v = result.value as Record<string, unknown>;
    assert.match(v.email as string, /^«EMAIL_\d+»$/);
    assert.equal(map.resolve(v.email as string), 'anna@example.com');
  });

  it('walks nested objects (user.name shape)', () => {
    const map = createTokenizeMap();
    const raw = { record: { user: { name: 'Jane Doe', age: 30 } } };
    const result = applyStableIdTokenization(
      raw,
      [{ path: 'record.user.name', idPath: 'record.user.age', type: 'PERSON' }],
      map,
    );
    assert.equal(result.replaced, 1);
    const name = (result.value as { record: { user: { name: string } } }).record.user
      .name;
    assert.match(name, /^«PERSON_\d+»$/);
  });

  it('applies multiple annotations independently', () => {
    const map = createTokenizeMap();
    const raw = {
      employees: [{ id: 1, name: 'Anna', email: 'anna@x.de' }],
    };
    const result = applyStableIdTokenization(
      raw,
      [
        { path: 'employees[].name', idPath: 'employees[].id', type: 'PERSON' },
        { path: 'employees[].email', idPath: 'employees[].id', type: 'EMAIL' },
      ],
      map,
    );
    assert.equal(result.replaced, 2);
    const emp = (result.value as { employees: Array<Record<string, unknown>> })
      .employees[0]!;
    assert.match(emp.name as string, /^«PERSON_\d+»$/);
    assert.match(emp.email as string, /^«EMAIL_\d+»$/);
  });

  it('silently skips on missing intermediate segments', () => {
    const map = createTokenizeMap();
    const raw = { other: { unrelated: true } };
    const result = applyStableIdTokenization(
      raw,
      [{ path: 'missing[].name', idPath: 'missing[].id', type: 'PERSON' }],
      map,
    );
    assert.equal(result.replaced, 0);
    // Zero leaves found on either side, lengths match (both 0), so
    // not counted as a shape-mismatch — annotation no-ops.
    assert.equal(result.skipped, 0);
  });
});

// ---------------------------------------------------------------------------
// Slice 2 — extended path grammar: top-level arrays + array indices.
// Odoo `search_read` returns a top-level array whose many2one fields
// are `[id, label]` tuples — neither shape was walkable in slice 1.
// ---------------------------------------------------------------------------

describe('applyStableIdTokenization · slice 2 — top-level arrays', () => {
  it('rewrites a field on a top-level array of objects', () => {
    const map = createTokenizeMap();
    const raw = [
      { id: 1, name: 'Anna Müller' },
      { id: 2, name: 'Bossity Schmidt' },
    ];
    const result = applyStableIdTokenization(
      raw,
      [{ path: '[].name', idPath: '[].id', type: 'PERSON' }],
      map,
    );
    assert.equal(result.replaced, 2);
    assert.equal(result.skipped, 0);
    const rows = result.value as Array<Record<string, unknown>>;
    assert.match(rows[0]?.name as string, /^«PERSON_\d+»$/);
    assert.match(rows[1]?.name as string, /^«PERSON_\d+»$/);
    assert.equal(map.resolve(rows[0]?.name as string), 'Anna Müller');
  });

  it('rewrites an array-of-leaf-strings via a trailing spread', () => {
    const map = createTokenizeMap();
    const raw = { emails: ['a@x.de', 'b@y.de'] };
    const result = applyStableIdTokenization(
      raw,
      [{ path: 'emails[]', idPath: 'emails[]', type: 'EMAIL' }],
      map,
    );
    assert.equal(result.replaced, 2);
    const emails = (result.value as { emails: string[] }).emails;
    assert.match(emails[0] as string, /^«EMAIL_\d+»$/);
    assert.match(emails[1] as string, /^«EMAIL_\d+»$/);
  });
});

describe('applyStableIdTokenization · slice 2 — array indices (Odoo many2one)', () => {
  // The exact shape from the live HR-Urlaubsranking trace: Odoo
  // `hr.leave` search_read, where `employee_id` is a `[id, name]`
  // many2one tuple and `holiday_status_id` is a `[id, label]` tuple.
  const hrLeaveRows = (): unknown => [
    {
      id: 1257,
      employee_id: [116, 'Jonathan Rüsche'],
      holiday_status_id: [1, 'Paid Time Off'],
      number_of_days: 1,
    },
    {
      id: 1085,
      employee_id: [162, 'Marvin Vomberg'],
      holiday_status_id: [1, 'Paid Time Off'],
      number_of_days: 1,
    },
    {
      id: 1192,
      employee_id: [190, 'Phillip Kalusek'],
      holiday_status_id: [1, 'Paid Time Off'],
      number_of_days: 0.5,
    },
  ];

  it('tokenises the label half of a many2one tuple, keeps the id', () => {
    const map = createTokenizeMap();
    const result = applyStableIdTokenization(
      hrLeaveRows(),
      [
        {
          path: '[].employee_id[1]',
          idPath: '[].employee_id[0]',
          type: 'PERSON',
        },
      ],
      map,
    );
    assert.equal(result.replaced, 3);
    assert.equal(result.skipped, 0);
    const rows = result.value as Array<Record<string, unknown>>;
    for (const row of rows) {
      const m2o = row.employee_id as unknown[];
      assert.equal(typeof m2o[0], 'number'); // id untouched
      assert.match(m2o[1] as string, /^«PERSON_\d+»$/); // label tokenised
    }
    // Restoration yields the original names.
    const firstLabel = (rows[0]?.employee_id as unknown[])[1] as string;
    assert.equal(map.resolve(firstLabel), 'Jonathan Rüsche');
  });

  it('handles an empty many2one relation (Odoo emits `false`)', () => {
    const map = createTokenizeMap();
    const raw = [
      { id: 1, employee_id: [116, 'Jonathan Rüsche'] },
      { id: 2, employee_id: false }, // unassigned relation
      { id: 3, employee_id: [190, 'Phillip Kalusek'] },
    ];
    const result = applyStableIdTokenization(
      raw,
      [{ path: '[].employee_id[1]', idPath: '[].employee_id[0]', type: 'PERSON' }],
      map,
    );
    // The `false` row contributes no leaf to either path — counts
    // stay aligned, the two real rows tokenise.
    assert.equal(result.replaced, 2);
    assert.equal(result.skipped, 0);
    const rows = result.value as Array<Record<string, unknown>>;
    assert.equal(rows[1]?.employee_id, false);
  });

  it('tokenises two many2one fields independently in one pass', () => {
    const map = createTokenizeMap();
    const result = applyStableIdTokenization(
      hrLeaveRows(),
      [
        { path: '[].employee_id[1]', idPath: '[].employee_id[0]', type: 'PERSON' },
        {
          path: '[].holiday_status_id[1]',
          idPath: '[].holiday_status_id[0]',
          type: 'ORG',
        },
      ],
      map,
    );
    assert.equal(result.replaced, 6); // 3 people + 3 status labels
    const rows = result.value as Array<Record<string, unknown>>;
    assert.match((rows[0]?.employee_id as unknown[])[1] as string, /^«PERSON_\d+»$/);
    assert.match(
      (rows[0]?.holiday_status_id as unknown[])[1] as string,
      /^«ORG_\d+»$/,
    );
  });

  it('skips the annotation on a malformed many2one (missing label)', () => {
    const map = createTokenizeMap();
    const raw = [
      { id: 1, employee_id: [116, 'Jonathan Rüsche'] },
      { id: 2, employee_id: [162] }, // malformed — no label slot
    ];
    const result = applyStableIdTokenization(
      raw,
      [{ path: '[].employee_id[1]', idPath: '[].employee_id[0]', type: 'PERSON' }],
      map,
    );
    // path[1] resolves 1 leaf (row 1 only), idPath[0] resolves 2 —
    // counts disagree, conservative skip of the whole annotation.
    assert.equal(result.replaced, 0);
    assert.equal(result.skipped, 1);
  });

  it('rejects malformed path strings (unclosed bracket, [foo], double dot)', () => {
    const map = createTokenizeMap();
    const raw = [{ employee_id: [1, 'Anna'] }];
    for (const bad of ['[].employee_id[1', '[].employee_id[foo]', '[]..name']) {
      const result = applyStableIdTokenization(
        raw,
        [{ path: bad, idPath: '[].employee_id[0]', type: 'PERSON' }],
        map,
      );
      assert.equal(result.replaced, 0, `path '${bad}' must not tokenise`);
      assert.equal(result.skipped, 1, `path '${bad}' must be skipped`);
    }
  });
});

describe('odooMany2OnePiiField / odooSearchReadPiiFields helpers', () => {
  it('odooMany2OnePiiField builds the [1]/[0] index paths', () => {
    const field = odooMany2OnePiiField('employee_id');
    assert.equal(field.path, '[].employee_id[1]');
    assert.equal(field.idPath, '[].employee_id[0]');
    assert.equal(field.type, undefined); // defaults to PERSON downstream
  });

  it('odooMany2OnePiiField honours type and recordsAt envelope', () => {
    const field = odooMany2OnePiiField('partner_id', {
      type: 'ORG',
      recordsAt: 'records',
    });
    assert.equal(field.path, 'records[].partner_id[1]');
    assert.equal(field.idPath, 'records[].partner_id[0]');
    assert.equal(field.type, 'ORG');
  });

  it('odooSearchReadPiiFields expands a field map', () => {
    const fields = odooSearchReadPiiFields({
      employee_id: 'PERSON',
      user_id: 'PERSON',
    });
    assert.equal(fields.length, 2);
    assert.deepEqual(fields[0], {
      path: '[].employee_id[1]',
      idPath: '[].employee_id[0]',
      type: 'PERSON',
    });
  });

  it('end-to-end: helper output tokenises the live hr.leave shape', () => {
    const map = createTokenizeMap();
    const raw = [
      { id: 1257, employee_id: [116, 'Jonathan Rüsche'] },
      { id: 1249, employee_id: [103, 'Dennis Zille'] },
      { id: 1253, employee_id: [198, 'Sophie Neumann'] },
    ];
    const result = applyStableIdTokenization(
      raw,
      odooSearchReadPiiFields({ employee_id: 'PERSON' }),
      map,
    );
    assert.equal(result.replaced, 3);
    assert.equal(result.skipped, 0);
    const rows = result.value as Array<Record<string, unknown>>;
    // No partial-name leak: the WHOLE name "Jonathan Rüsche" is one
    // token, not "«PERSON_N» Rüsche".
    const label = (rows[0]?.employee_id as unknown[])[1] as string;
    assert.match(label, /^«PERSON_\d+»$/);
    assert.equal(map.resolve(label), 'Jonathan Rüsche');
  });
});
