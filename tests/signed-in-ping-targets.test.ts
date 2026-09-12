import assert from 'node:assert/strict';
import test from 'node:test';

import { selectConnectionPingTargets } from '../packages/signed-in/src/ping-targets.js';

// Proves the explicit all-connections mode includes secondary aliases without changing normal selection rules.
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
});
