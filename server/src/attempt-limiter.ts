/**
 * Attempt budgets for the public authentication endpoints.
 *
 * Each client has its own budget of attempts per window, so the failures of
 * one client cannot lock another out. An attempt is taken from the budget when
 * the request is admitted, before any asynchronous work, so requests arriving
 * together cannot all pass the check before the first failure is recorded.
 */

import { isIPv4 } from 'node:net';

type Budget = { used: number; resetAt: number };

export class AttemptLimiter {
  private readonly budgets = new Map<string, Budget>();

  constructor(
    private readonly maxAttempts: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
    // Bounds the memory an attacker can claim by arriving from many addresses.
    private readonly maxClients = 10_000,
  ) {}

  /**
   * Takes one attempt from the client's budget, or returns null when the
   * budget is spent. The returned function gives the attempt back: call it
   * only when the request turned out not to be a failed guess.
   */
  admit(client: string): (() => void) | null {
    const now = this.now();
    let budget = this.budgets.get(client);
    if (budget && now > budget.resetAt) {
      this.budgets.delete(client);
      budget = undefined;
    }

    if (!budget) {
      if (this.budgets.size >= this.maxClients) this.dropExpired(now);
      // Still full of live budgets: evicting one would hand its client a
      // fresh set of guesses, so the newcomer is the one refused.
      if (this.budgets.size >= this.maxClients) return null;
      budget = { used: 0, resetAt: now + this.windowMs };
      this.budgets.set(client, budget);
    }

    if (budget.used >= this.maxAttempts) return null;
    budget.used += 1;

    const admitted = budget;
    let givenBack = false;
    return () => {
      if (givenBack) return;
      givenBack = true;
      admitted.used -= 1;
      if (admitted.used === 0 && this.budgets.get(client) === admitted) {
        this.budgets.delete(client);
      }
    };
  }

  private dropExpired(now: number): void {
    for (const [client, budget] of this.budgets) {
      if (now > budget.resetAt) this.budgets.delete(client);
    }
  }
}

/**
 * The budget a peer address belongs to. IPv4 addresses each get their own. An
 * IPv6 host can pick any address within its /64, so the whole /64 shares one:
 * otherwise a client could give itself a fresh budget for every request.
 */
export function clientKey(address: string | undefined): string {
  if (!address) return 'unknown';

  // IPv4 peers of a dual-stack listener arrive as `::ffff:a.b.c.d`.
  const ipv4 = address.replace(/^::ffff:/i, '');
  if (isIPv4(ipv4)) return ipv4;

  const [head, tail] = address.split('%')[0].toLowerCase().split('::');
  const leading = head ? head.split(':') : [];
  const trailing = tail ? tail.split(':') : [];
  const elided = tail === undefined ? 0 : Math.max(0, 8 - leading.length - trailing.length);
  const groups = [...leading, ...Array<string>(elided).fill('0'), ...trailing];
  return groups.slice(0, 4).map((group) => group.replace(/^0+(?=.)/, '')).join(':');
}
