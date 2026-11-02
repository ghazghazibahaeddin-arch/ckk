/**
 * CCK Error Classes
 */

import { ExecutionVerdict } from './types.js';

export class CCKError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CCKError';
  }
}

export class CCKConnectionError extends CCKError {
  constructor(message: string) {
    super(message);
    this.name = 'CCKConnectionError';
  }
}

export class CCKActionBlockedError extends CCKError {
  public readonly verdict: ExecutionVerdict;

  constructor(verdict: ExecutionVerdict) {
    super(`CCK Action Gate BLOCKED action: ${verdict.reason} (Rule: ${verdict.matched_policies?.[0]?.rule_name || 'Safety Guardrail'})`);
    this.name = 'CCKActionBlockedError';
    this.verdict = verdict;
  }
}

export class CCKApprovalRequiredError extends CCKError {
  public readonly verdict: ExecutionVerdict;

  constructor(verdict: ExecutionVerdict) {
    super(`CCK Action requires human approval: ${verdict.reason}`);
    this.name = 'CCKApprovalRequiredError';
    this.verdict = verdict;
  }
}
