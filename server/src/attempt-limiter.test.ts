import assert from 'node:assert/strict';
import { test } from 'node:test';

import { AttemptLimiter, clientKey } from './attempt-limiter.js';

const WINDOW_MS = 15 * 60 * 1000;

function limiterAt(clock: { now: number }, maxClients?: number): AttemptLimiter {
  return new AttemptLimiter(5, WINDOW_MS, () => clock.now, maxClients);
}

function admitted(limiter: AttemptLimiter, client: string, requests: number): number {
  return Array.from({ length: requests }, () => limiter.admit(client)).filter(Boolean).length;
}

test('one client spending its budget does not limit another', () => {
  const limiter = limiterAt({ now: 0 });

  assert.equal(admitted(limiter, 'attacker', 12), 5);
  assert.equal(limiter.admit('attacker'), null);
  assert.equal(admitted(limiter, 'operator', 1), 1);
});

test('an attempt counts from admission, before its outcome is known', () => {
  const limiter = limiterAt({ now: 0 });

  // Twelve requests admitted before any of them has failed: a counter that
  // only moved on failure would let all twelve through.
  const attempts = Array.from({ length: 12 }, () => limiter.admit('client'));
  assert.equal(attempts.filter(Boolean).length, 5);
});

test('an attempt that is given back can be used again, once', () => {
  const limiter = limiterAt({ now: 0 });
  const giveBack = limiter.admit('client');
  assert.ok(giveBack);
  assert.equal(admitted(limiter, 'client', 4), 4);
  assert.equal(limiter.admit('client'), null);

  giveBack();
  giveBack();
  assert.equal(admitted(limiter, 'client', 3), 1);
});

test('a budget is restored when its window has passed', () => {
  const clock = { now: 0 };
  const limiter = limiterAt(clock);
  const stale = limiter.admit('client');
  assert.ok(stale);
  assert.equal(admitted(limiter, 'client', 4), 4);

  clock.now = WINDOW_MS;
  assert.equal(limiter.admit('client'), null);

  clock.now = WINDOW_MS + 1;
  assert.equal(admitted(limiter, 'client', 5), 5);
  // An attempt from the previous window cannot be returned to this one.
  stale();
  assert.equal(limiter.admit('client'), null);
});

test('the number of tracked clients is bounded without resetting anyone', () => {
  const clock = { now: 0 };
  const limiter = limiterAt(clock, 2);
  assert.equal(admitted(limiter, 'first', 5), 5);
  const giveBack = limiter.admit('second');
  assert.ok(giveBack);

  assert.equal(limiter.admit('third'), null);
  assert.equal(limiter.admit('first'), null, 'the full table did not evict a spent budget');

  // A client with nothing outstanding leaves the table.
  giveBack();
  assert.equal(admitted(limiter, 'third', 1), 1);

  clock.now = WINDOW_MS + 1;
  assert.equal(admitted(limiter, 'fourth', 1), 1);
});

test('an IPv4 peer is keyed by its address, mapped or not', () => {
  assert.equal(clientKey('192.168.1.20'), '192.168.1.20');
  assert.equal(clientKey('::ffff:192.168.1.20'), '192.168.1.20');
  assert.notEqual(clientKey('192.168.1.20'), clientKey('192.168.1.21'));
});

test('IPv6 peers share a budget within a /64', () => {
  const key = clientKey('2001:db8:1:2:aaaa:bbbb:cccc:dddd');
  assert.equal(key, '2001:db8:1:2');
  assert.equal(clientKey('2001:db8:1:2::1'), key);
  assert.equal(clientKey('2001:0DB8:0001:0002:0:0:0:1'), key);
  assert.notEqual(clientKey('2001:db8:1:3::1'), key);

  assert.equal(clientKey('::1'), '0:0:0:0');
  assert.equal(clientKey('fe80::1%eth0'), 'fe80:0:0:0');
  assert.equal(clientKey('2001:db8::1:2:3:4:5'), '2001:db8:0:1');
});

test('a request without a peer address still has a budget', () => {
  assert.equal(clientKey(undefined), 'unknown');
});
