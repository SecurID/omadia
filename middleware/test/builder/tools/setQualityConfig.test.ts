import { describe, it, beforeEach, afterEach } from 'node:test';
import { strict as assert } from 'node:assert';

import { setQualityConfigTool } from '../../../src/plugins/builder/tools/setQualityConfig.js';
import {
  createBuilderToolHarness,
  type BuilderToolHarness,
} from '../fixtures/builderToolHarness.js';

/**
 * `set_quality_config` Builder-Tool tests.
 *
 * Covers the Phase-1 Kemia surface (sycophancy level + boundary presets
 * + custom lines) plus the F4 (#54) warnings-for-unknown-presets path.
 */
describe('setQualityConfigTool', () => {
  let harness: BuilderToolHarness;

  beforeEach(async () => {
    harness = await createBuilderToolHarness();
  });

  afterEach(async () => {
    await harness.dispose();
  });

  it('writes spec.quality on the active draft + emits spec_patch + schedules rebuild', async () => {
    const result = await setQualityConfigTool.run(
      {
        sycophancy: 'medium',
        boundaries: {
          presets: ['no-pii', 'no-medical-data'],
          custom: ['no PII please'],
        },
      },
      harness.context(),
    );

    assert.equal(result.ok, true);
    if (!result.ok) return;

    assert.deepEqual(result.applied, [
      {
        op: 'add',
        path: '/quality',
        value: {
          sycophancy: 'medium',
          boundaries: {
            presets: ['no-pii', 'no-medical-data'],
            custom: ['no PII please'],
          },
        },
      },
    ]);
    assert.equal(result.warnings, undefined, 'no warnings expected for known IDs');

    const reloaded = await harness.draftStore.load(
      harness.userEmail,
      harness.draftId,
    );
    assert.ok(reloaded);
    assert.deepEqual(reloaded.spec.quality, {
      sycophancy: 'medium',
      boundaries: {
        presets: ['no-pii', 'no-medical-data'],
        custom: ['no PII please'],
      },
    });

    assert.equal(harness.events.length, 1);
    assert.equal(harness.events[0]!.type, 'spec_patch');
    assert.equal(harness.rebuilds.length, 1);
  });

  it('persists as-submitted even when boundary preset IDs are unknown (forward compat)', async () => {
    const result = await setQualityConfigTool.run(
      {
        boundaries: {
          presets: ['no-pii', 'not-a-real-preset', 'also-bogus'],
          custom: [],
        },
      },
      harness.context(),
    );

    assert.equal(result.ok, true);
    if (!result.ok) return;

    // Spec persists exactly what was submitted — the unknown IDs survive
    // so future kemia presets land cleanly without a migration.
    const reloaded = await harness.draftStore.load(
      harness.userEmail,
      harness.draftId,
    );
    assert.ok(reloaded);
    assert.deepEqual(reloaded.spec.quality?.boundaries?.presets, [
      'no-pii',
      'not-a-real-preset',
      'also-bogus',
    ]);
  });

  it('surfaces unknown preset IDs via warnings[]', async () => {
    const result = await setQualityConfigTool.run(
      {
        boundaries: {
          presets: ['no-pii', 'not-a-real-preset', 'also-bogus'],
          custom: [],
        },
      },
      harness.context(),
    );

    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.deepEqual(result.warnings, [
      'unknown preset: not-a-real-preset',
      'unknown preset: also-bogus',
    ]);
  });

  it('emits no warnings when all preset IDs are known', async () => {
    const result = await setQualityConfigTool.run(
      {
        sycophancy: 'high',
        boundaries: { presets: ['no-pii', 'no-commitments'], custom: [] },
      },
      harness.context(),
    );
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.warnings, undefined);
  });

  it('emits no warnings when boundaries block is absent', async () => {
    const result = await setQualityConfigTool.run(
      { sycophancy: 'low' },
      harness.context(),
    );
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.warnings, undefined);
  });
});
