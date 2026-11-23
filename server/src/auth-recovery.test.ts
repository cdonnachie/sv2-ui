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

test('first-password setup succeeds for exactly one of several concurrent requests', async () => {
  const { base, configDir, stop } = await startServer();
  const credentialFile = path.join(configDir, 'credential.json');
  const post = (route: string, body: Record<string, unknown>) =>
    fetch(`${base}${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

  // Sends one setup per password at once, and returns the password that won.
  const raceSetups = async (passwords: string[]): Promise<string> => {
    const responses = await Promise.all(
      passwords.map((password) => post('/api/auth/setup-password', { password })),
    );
    const bodies = (await Promise.all(responses.map((response) => response.json()))) as Array<{
      recoveryKey?: string;
      error?: string;
    }>;

    const winners = responses.flatMap((response, index) => (response.status === 200 ? [index] : []));
    assert.equal(winners.length, 1, `statuses: ${responses.map((response) => response.status).join(' ')}`);
    const [winner] = winners;

    responses.forEach((response, index) => {
      if (index === winner) return;
      assert.equal(response.status, 409);
      assert.deepEqual(bodies[index], { error: 'A password has already been set.' });
      assert.deepEqual(response.headers.getSetCookie(), [], 'a refused setup holds no session');
    });

    // The one session issued is valid, and what is stored is the winner's.
    const [sessionCookie] = responses[winner].headers.getSetCookie();
    const state = await fetch(`${base}/api/auth/state`, { headers: { Cookie: sessionCookie.split(';')[0] } });
    assert.equal(((await state.json()) as { authenticated: boolean }).authenticated, true);
    assert.equal((await post('/api/auth/login', { password: passwords[winner] })).status, 200);
    const recovered = await post('/api/auth/recover', {
      recoveryKey: bodies[winner].recoveryKey,
      newPassword: `${passwords[winner]}-recovered`,
    });
    assert.equal(recovered.status, 200);

    return passwords[winner];
  };

  try {
    const first = await raceSetups(Array.from({ length: 6 }, (_, index) => `first-password-${index}`));

    // Removing the credential file reopens setup, again for a single request.
    await rm(credentialFile);
    const second = await raceSetups(Array.from({ length: 6 }, (_, index) => `second-password-${index}`));

    assert.equal((await post('/api/auth/login', { password: `${first}-recovered` })).status, 401);
    assert.equal((await post('/api/auth/login', { password: `${second}-recovered` })).status, 200);
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('a recovery key completes a single password reset, even for requests sent at once', async () => {
  const { base, configDir, stop } = await startServer();
  const post = (route: string, body: Record<string, unknown>) =>
    fetch(`${base}${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  try {
    const setup = await post('/api/auth/setup-password', { password: 'sup3rsecret' });
    assert.equal(setup.status, 200);
    const { recoveryKey } = (await setup.json()) as { recoveryKey: string };

    const passwords = ['first-new-password', 'second-new-password', 'third-new-password'];
    const responses = await Promise.all(
      passwords.map((newPassword) => post('/api/auth/recover', { recoveryKey, newPassword })),
    );
    const bodies = (await Promise.all(responses.map((response) => response.json()))) as Array<{
      recoveryKey?: string;
      error?: string;
    }>;

    const winners = responses.flatMap((response, index) => (response.status === 200 ? [index] : []));
    assert.equal(winners.length, 1, `statuses: ${responses.map((response) => response.status).join(' ')}`);
    const [winner] = winners;
    const loser = winner === 0 ? 1 : 0;

    // The others are refused as if the key were wrong, which by then it is.
    responses.forEach((response, index) => {
      if (index === winner) return;
      assert.equal(response.status, 401);
      assert.deepEqual(bodies[index], { error: 'Invalid recovery key.' });
    });

    // What is stored is what the one successful reset set and returned.
    assert.equal((await post('/api/auth/login', { password: passwords[loser] })).status, 401);
    assert.equal((await post('/api/auth/login', { password: passwords[winner] })).status, 200);
    const again = await post('/api/auth/recover', {
      recoveryKey: bodies[winner].recoveryKey,
      newPassword: 'fourth-new-password',
    });
    assert.equal(again.status, 200);
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('a recovery key requested during a recovery neither undoes it nor is issued', async () => {
  const { base, configDir, stop } = await startServer();
  const post = (route: string, body: Record<string, unknown>, cookie = '') =>
    fetch(`${base}${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify(body),
    });
  const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  try {
    const setup = await post('/api/auth/setup-password', { password: 'sup3rsecret' });
    assert.equal(setup.status, 200);
    const { recoveryKey } = (await setup.json()) as { recoveryKey: string };
    const sessionCookie = setup.headers.getSetCookie()[0].split(';')[0];

    const recovering = post('/api/auth/recover', { recoveryKey, newPassword: 'recovered-password' });
    // Let the recovery start, then keep asking for a new key from the session
    // it is about to revoke. The requests that arrive while it is still
    // hashing pass the session check, and must not act once it has finished.
    await pause(50);
    const regenerating: Array<Promise<Response>> = [];
    for (let i = 0; i < 40; i += 1) {
      regenerating.push(
        post('/api/auth/recovery-key/regenerate', { currentPassword: 'sup3rsecret' }, sessionCookie),
      );
      await pause(10);
    }

    const recovered = await recovering;
    assert.equal(recovered.status, 200);
    const recoveredBody = (await recovered.json()) as { recoveryKey: string };

    for (const response of await Promise.all(regenerating)) {
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), { error: 'Authentication required' });
    }

    // The recovered password and the recovery key it came with are the ones stored.
    assert.equal((await post('/api/auth/login', { password: 'sup3rsecret' })).status, 401);
    assert.equal((await post('/api/auth/login', { password: 'recovered-password' })).status, 200);
    const again = await post('/api/auth/recover', {
      recoveryKey: recoveredBody.recoveryKey,
      newPassword: 'recovered-again',
    });
    assert.equal(again.status, 200);
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('changing the password ends every session but the one that changed it', async () => {
  const { base, configDir, stop } = await startServer();
  const post = (route: string, body: Record<string, unknown>, cookie = '') =>
    fetch(`${base}${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify(body),
    });
  const sessionCookie = (response: Response) => response.headers.getSetCookie()[0].split(';')[0];
  const isAuthenticated = async (cookie: string) =>
    ((await (await fetch(`${base}/api/auth/state`, { headers: { Cookie: cookie } })).json()) as {
      authenticated: boolean;
    }).authenticated;
  try {
    const setup = await post('/api/auth/setup-password', { password: 'sup3rsecret' });
    assert.equal(setup.status, 200);
    const operator = sessionCookie(setup);
    const intruder = sessionCookie(await post('/api/auth/login', { password: 'sup3rsecret' }));
    assert.equal(await isAuthenticated(operator), true);
    assert.equal(await isAuthenticated(intruder), true);

    // A refused change leaves every session alone.
    const refused = await post(
      '/api/auth/change-password',
      { currentPassword: 'not-the-password', newPassword: 'n3wpassword!' },
      operator,
    );
    assert.equal(refused.status, 401);
    assert.equal(await isAuthenticated(intruder), true);

    const changed = await post(
      '/api/auth/change-password',
      { currentPassword: 'sup3rsecret', newPassword: 'n3wpassword!' },
      operator,
    );
    assert.equal(changed.status, 200);
    assert.equal(await isAuthenticated(operator), true);
    assert.equal(await isAuthenticated(intruder), false);

    // The ended session cannot be used to keep access.
    const regenerate = await post('/api/auth/recovery-key/regenerate', { currentPassword: 'n3wpassword!' }, intruder);
    assert.equal(regenerate.status, 401);
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});

test('a login with the old password leaves no session behind a recovery', async () => {
  const { base, configDir, stop } = await startServer();
  const post = (route: string, body: Record<string, unknown>) =>
    fetch(`${base}${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  try {
    const setup = await post('/api/auth/setup-password', { password: 'sup3rsecret' });
    assert.equal(setup.status, 200);
    const { recoveryKey } = (await setup.json()) as { recoveryKey: string };

    const recovering = post('/api/auth/recover', { recoveryKey, newPassword: 'recovered-password' });
    // Let the recovery start, then keep logging in with the password it is
    // replacing. A login that read the old credential before the recovery
    // wrote, and finished verifying after it revoked the sessions, would get
    // a session that outlives the password it was obtained with.
    await pause(50);
    const loggingIn: Array<Promise<Response>> = [];
    for (let i = 0; i < 30; i += 1) {
      loggingIn.push(post('/api/auth/login', { password: 'sup3rsecret' }));
      await pause(10);
    }

    assert.equal((await recovering).status, 200);

    for (const response of await Promise.all(loggingIn)) {
      const [cookie] = response.headers.getSetCookie();
      if (!cookie) continue;
      const state = await fetch(`${base}/api/auth/state`, { headers: { Cookie: cookie.split(';')[0] } });
      assert.equal(
        ((await state.json()) as { authenticated: boolean }).authenticated,
        false,
        'a session obtained with the replaced password is still valid',
      );
    }
  } finally {
    stop();
    await rm(configDir, { recursive: true, force: true });
  }
});
