import assert from 'node:assert/strict';
import test from 'node:test';

import {
  formatConnectionRepairTargets,
  selectConnectionPingTargets,
} from '../packages/signed-in/src/ping-targets.js';

// Proves all-connections mode includes secondary aliases and carries exact failures into repair.
test('ping targets distinguish selected services from every saved connection', () => {
  const services = [
    {
      accounts: [
        { account: 'personal', default: false },
        { account: 'work', default: true },
      ],
      id: 'github',
    },
    {
      accounts: [
        { account: 'staging', default: true },
        { account: 'production', default: false },
      ],
      id: 'datocms',
      projectAccount: 'production',
    },
    { accounts: [], id: 'stripe' },
  ];

  assert.deepEqual(selectConnectionPingTargets(services, false), [
    { account: 'work', service: 'github' },
    { account: 'production', service: 'datocms' },
  ]);
  assert.deepEqual(selectConnectionPingTargets(services, true), [
    { account: 'personal', service: 'github' },
    { account: 'work', service: 'github' },
    { account: 'staging', service: 'datocms' },
    { account: 'production', service: 'datocms' },
  ]);
  assert.deepEqual(formatConnectionRepairTargets([
    { account: 'project-universal', service: 'polar' },
    { account: 'example-project', service: 'shopify' },
  ]), [
    'polar@project-universal',
    'shopify@example-project',
  ]);
});
