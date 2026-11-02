/**
 * CCK Action Gate Fail-Closed Guard
 *
 * Wraps or intercepts agent tool execution so that an action is NEVER
 * executed unless CCK returns an authoritative ALLOW verdict.
 */

import { CCKClient } from './client.js';
import { AgentAction, ExecutionVerdict } from './types.js';
import { CCKActionBlockedError, CCKApprovalRequiredError } from './errors.js';

export interface GuardOptions {
  client: CCKClient;
  action: AgentAction;
  onAllow?: (verdict: ExecutionVerdict) => void;
  onBlock?: (verdict: ExecutionVerdict) => void;
}

/**
 * Execute a protected agent tool or external mutation with fail-closed safety.
 *
 * @param options Guard configuration with CCK client and action payload
 * @param toolFn Function that performs the actual tool execution
 * @returns The return value of toolFn if allowed
 * @throws CCKActionBlockedError if the action is blocked by CCK
 * @throws CCKApprovalRequiredError if human-in-the-loop signoff is required
 * @throws CCKConnectionError if CCK is unreachable (fail-closed)
 */
export async function withCCKGuard<T>(
  options: GuardOptions,
  toolFn: () => Promise<T> | T
): Promise<T> {
  const verdict = await options.client.evaluateAction(options.action);

  if (verdict.decision === 'ALLOW') {
    if (options.onAllow) {
      options.onAllow(verdict);
    }
    return await toolFn();
  }

  if (verdict.decision === 'BLOCK') {
    if (options.onBlock) {
      options.onBlock(verdict);
    }
    throw new CCKActionBlockedError(verdict);
  }

  if (verdict.decision === 'REQUIRE_APPROVAL') {
    throw new CCKApprovalRequiredError(verdict);
  }

  // Fall-through for REVALIDATE or any non-ALLOW verdict (strict fail-closed)
  throw new CCKActionBlockedError(verdict);
}
