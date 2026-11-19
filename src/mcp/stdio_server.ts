#!/usr/bin/env node
/**
 * CCK Model Context Protocol (MCP) Stdio Runtime Enforcement Bridge
 *
 * Implements newline-delimited JSON-RPC 2.0 over stdio and forwards ALL
 * tool discovery and tool calls fail-closed to the live CCK Control Plane
 * MCP Runtime Enforcement Gateway (/api/v1/mcp). Zero mock stubs.
 */

import * as readline from 'readline';

const CCK_BASE_URL = (process.env.CCK_BASE_URL || 'http://127.0.0.1:3000').replace(/\/$/, '');
const CCK_API_KEY = process.env.CCK_API_KEY || '';
const CCK_SESSION_TOKEN = process.env.CCK_SESSION_TOKEN || '';
const REQUEST_TIMEOUT_MS = Math.max(500, Number(process.env.CCK_MCP_TIMEOUT_MS || 8000));

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

async function forwardJsonRpcToControlPlane(reqObj: Record<string, unknown>): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  const bearer = CCK_API_KEY || CCK_SESSION_TOKEN;
  if (bearer) {
    headers['Authorization'] = `Bearer ${bearer}`;
  }
  if (CCK_API_KEY && CCK_API_KEY.startsWith('cck_live_')) {
    headers['x-api-key'] = CCK_API_KEY;
  }

  try {
    const res = await fetch(`${CCK_BASE_URL}/api/v1/mcp`, {
      method: 'POST',
      headers,
      body: JSON.stringify(reqObj),
      signal: controller.signal,
    });
    clearTimeout(timer);

    const payload = (await res.json()) as Record<string, unknown>;
    return payload;
  } catch (err: unknown) {
    clearTimeout(timer);
    // Strict Fail-Closed Guarantee: Never synthesize ALLOW when CCK Control Plane is unreachable!
    const reason =
      err instanceof Error
        ? `CCK MCP Gateway unreachable (${err.message}). Fail-closed BLOCK enforced.`
        : 'CCK MCP Gateway unreachable. Fail-closed BLOCK enforced.';

    if (reqObj.method === 'tools/call') {
      return {
        jsonrpc: '2.0',
        id: reqObj.id ?? null,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                allowed: false,
                decision: 'BLOCK',
                downstream_dispatched: false,
                reason,
              }),
            },
          ],
          isError: true,
        },
      };
    }

    return {
      jsonrpc: '2.0',
      id: reqObj.id ?? null,
      error: {
        code: -32002,
        message: reason,
      },
    };
  }
}

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let reqObj: Record<string, unknown>;
  try {
    reqObj = JSON.parse(trimmed) as Record<string, unknown>;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    process.stdout.write(
      JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: `Parse error: ${message}` } }) + '\n'
    );
    return;
  }

  forwardJsonRpcToControlPlane(reqObj)
    .then((resp) => {
      process.stdout.write(JSON.stringify(resp) + '\n');
    })
    .catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      process.stdout.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: reqObj.id ?? null,
          error: { code: -32002, message: `Fail-closed gateway bridge error: ${message}` },
        }) + '\n'
      );
    });
});
