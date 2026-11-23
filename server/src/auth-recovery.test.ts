import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { test } from 'node:test';
import { mkdtemp, rm, writeFile, access } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SERVER_DIR = path.dirname(fileURLToPath(import.meta.url));
const SERVER_ROOT = path.join(SERVER_DIR, '..');

async function startServer(): Promise<{
  base: string;
  configDir: string;
  stop: () => void;
}> {
  const configDir = await mkdtemp(path.join(os.tmpdir(), 'sv2-ui-auth-'));
  const port = 4200 + Math.floor(Math.random() * 300);
  const child: ChildProcess = spawn(
    'node',
    ['--import', 'tsx', 'src/index.ts'],
    {
      cwd: SERVER_ROOT,
      env: { ...process.env, CONFIG_DIR: configDir, PORT: String(port), NODE_ENV: 'test' },
      stdio: 'ignore',
    },
  );

  const base = `http://localhost:${port}`;
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${base}/api/health`);
      if (res.ok) break;
    } catch {
      // server not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }

  return { base, configDir, stop: () => child.kill('SIGKILL') };
}

test('recover resets the password but keeps the mining configuration', async () => {
  const { base, configDir, stop } = await startServer();
  try {
    const setup = await fetch(`${base}/api/auth/setup-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'sup3rsecret' }),
    });
    assert.equal(setup.status, 200);
    const setupBody = (await setup.json()) as { recoveryKey?: string };
    assert.equal(typeof setupBody.recoveryKey, 'string');

    const state = (await (await fetch(`${base}/api/auth/state`)).json()) as {
      passwordSet: boolean;
      recoveryKeySet: boolean;
    };
    assert.equal(state.passwordSet, true);
    assert.equal(state.recoveryKeySet, true);

    // Simulate an existing mining configuration that must survive recovery.
    await writeFile(path.join(configDir, 'translator.toml'), '# config');

    const wrong = await fetch(`${base}/api/auth/recover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recoveryKey: 'not-the-right-key', newPassword: 'n3wpassword!' }),
    });
    assert.equal(wrong.status, 401);

    const recover = await fetch(`${base}/api/auth/recover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recoveryKey: setupBody.recoveryKey, newPassword: 'n3wpassword!' }),
    });
    assert.equal(recover.status, 200);
    assert.equal((await recover.json()).success, true);

    const stateAfter = (await (await fetch(`${base}/api/auth/state`)).json()) as {
      passwordSet: boolean;
    };
    assert.equal(stateAfter.passwordSet, true);

    // Config volume preserved across the password reset.
    await access(path.join(configDir, 'translator.toml'));
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('recover is rate limited after repeated failures', async () => {
  const { base, configDir, stop } = await startServer();
  try {
    const setup = await fetch(`${base}/api/auth/setup-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'sup3rsecret' }),
    });
    assert.equal(setup.status, 200);

    let lastStatus = 0;
    for (let i = 0; i < 6; i += 1) {
      const res = await fetch(`${base}/api/auth/recover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recoveryKey: 'wrong', newPassword: 'n3wpassword!' }),
      });
      lastStatus = res.status;
    }
    assert.equal(lastStatus, 429);
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('wrong attempts sent at once cannot exceed the attempt limit', async () => {
  const { base, configDir, stop } = await startServer();
  try {
    const setup = await fetch(`${base}/api/auth/setup-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'sup3rsecret' }),
    });
    assert.equal(setup.status, 200);

    const guesses: Array<[string, Record<string, string>]> = [
      ['/api/auth/login', { password: 'wrong-guess' }],
      ['/api/auth/recover', { recoveryKey: 'wrong-guess', newPassword: 'n3wpassword!' }],
    ];
    for (const [route, body] of guesses) {
      const statuses = await Promise.all(
        Array.from({ length: 12 }, async () => {
          const res = await fetch(`${base}${route}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          return res.status;
        }),
      );
      // 401 means the guess was verified, 429 that it was refused unverified.
      assert.equal(statuses.filter((status) => status === 401).length, 5, `${route}: ${statuses.join(' ')}`);
      assert.equal(statuses.filter((status) => status === 429).length, 7, `${route}: ${statuses.join(' ')}`);
    }
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('the failed attempts of one client do not lock out another', async () => {
  const { base, configDir, stop } = await startServer();
  // Two clients on one machine: the IPv4 and the IPv6 loopback address.
  const { port } = new URL(base);
  const attacker = `http://127.0.0.1:${port}`;
  const operator = `http://[::1]:${port}`;
  const post = (origin: string, route: string, body: Record<string, unknown>) =>
    fetch(`${origin}${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  try {
    const setup = await post(operator, '/api/auth/setup-password', { password: 'sup3rsecret' });
    assert.equal(setup.status, 200);
    const { recoveryKey } = (await setup.json()) as { recoveryKey: string };

    for (let i = 0; i < 5; i += 1) {
      assert.equal((await post(attacker, '/api/auth/login', { password: 'wrong-guess' })).status, 401);
      assert.equal(
        (await post(attacker, '/api/auth/recover', { recoveryKey: 'wrong-guess', newPassword: 'n3wpassword!' })).status,
        401,
      );
    }

    // The attacker is out of attempts, even with the right credentials.
    assert.equal((await post(attacker, '/api/auth/login', { password: 'sup3rsecret' })).status, 429);
    assert.equal(
      (await post(attacker, '/api/auth/recover', { recoveryKey, newPassword: 'n3wpassword!' })).status,
      429,
    );

    // The operator is not.
    assert.equal((await post(operator, '/api/auth/login', { password: 'sup3rsecret' })).status, 200);
    assert.equal(
      (await post(operator, '/api/auth/recover', { recoveryKey, newPassword: 'n3wpassword!' })).status,
      200,
    );
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('recover rejects a missing newPassword', async () => {
  const { base, configDir, stop } = await startServer();
  try {
    const setup = await fetch(`${base}/api/auth/setup-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'sup3rsecret' }),
    });
    assert.equal(setup.status, 200);
    const setupBody = (await setup.json()) as { recoveryKey?: string };

    const res = await fetch(`${base}/api/auth/recover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recoveryKey: setupBody.recoveryKey }),
    });
    assert.equal(res.status, 400);
    const body = (await res.json()) as { error?: string };
    assert.match(body.error ?? '', /password/i);
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('recover rejects a weak newPassword', async () => {
  const { base, configDir, stop } = await startServer();
  try {
    const setup = await fetch(`${base}/api/auth/setup-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'sup3rsecret' }),
    });
    assert.equal(setup.status, 200);
    const setupBody = (await setup.json()) as { recoveryKey?: string };

    const res = await fetch(`${base}/api/auth/recover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recoveryKey: setupBody.recoveryKey, newPassword: 'short' }),
    });
    assert.equal(res.status, 400);
    const body = (await res.json()) as { error?: string };
    assert.match(body.error ?? '', /at least/i);
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('login is rate limited after repeated failures', async () => {
  const { base, configDir, stop } = await startServer();
  try {
    const setup = await fetch(`${base}/api/auth/setup-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'sup3rsecret' }),
    });
    assert.equal(setup.status, 200);

    let lastStatus = 0;
    for (let i = 0; i < 6; i += 1) {
      const res = await fetch(`${base}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'wrong' }),
      });
      lastStatus = res.status;
    }
    assert.equal(lastStatus, 429);
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('auth state reports needsSetup only until a password exists', async () => {
  const { base, configDir, stop } = await startServer();
  const stateFile = path.join(configDir, 'state.json');
  const needsSetup = async () =>
    ((await (await fetch(`${base}/api/auth/state`)).json()) as { needsSetup?: boolean }).needsSetup;
  try {
    assert.equal(await needsSetup(), true);

    await writeFile(stateFile, JSON.stringify({ configured: false }));
    assert.equal(await needsSetup(), true);

    await writeFile(stateFile, JSON.stringify({
      configured: true,
      shouldBeRunning: false,
      data: { miningMode: 'pool', mode: 'no-jd', pool: null, fallbackPools: [], bitcoin: null, jdc: null, translator: null },
    }));
    assert.equal(await needsSetup(), false);

    await writeFile(stateFile, '{ not json');
    assert.equal(await needsSetup(), false);

    const setup = await fetch(`${base}/api/auth/setup-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'sup3rsecret' }),
    });
    assert.equal(setup.status, 200);
    assert.equal(await needsSetup(), undefined);
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});
