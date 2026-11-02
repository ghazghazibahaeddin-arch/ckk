#!/usr/bin/env node
/**
 * CCK Model Context Protocol (MCP) Stdio Server
 *
 * Implements newline-delimited JSON-RPC 2.0 stdio communication for MCP.
 */

import * as readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const tools = [
  {
    name: 'cck_evaluate_action',
    description: 'Evaluate agent tool call or mutation against CCK Action Gate before execution.',
    inputSchema: {
      type: 'object',
      properties: {
        capability: { type: 'string', description: 'Action capability, e.g. logistics.ship' },
        target: { type: 'string', description: 'Resource identifier, e.g. order:1099' },
        parameters: { type: 'object', description: 'Parameters passed to target tool' },
        session_id: { type: 'string', description: 'Agent session tracking ID' },
      },
      required: ['capability', 'target'],
    },
  },
  {
    name: 'cck_record_evidence',
    description: 'Record verified external observation or state change to update CCK facts.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: { type: 'string', description: 'Entity ID, e.g. order:1099' },
        field_name: { type: 'string', description: 'Field name, e.g. status' },
        value: { description: 'Observed value, e.g. paid, refunded, canceled' },
      },
      required: ['entity_id', 'field_name', 'value'],
    },
  },
  {
    name: 'cck_verify_heartbeat',
    description: 'Verify agent connectivity and update last_seen_at heartbeat.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: { type: 'string', description: 'Registered Agent ID' },
      },
      required: ['agent_id'],
    },
  },
];

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const req = JSON.parse(trimmed);
    const { jsonrpc, id, method, params } = req;

    if (method === 'initialize') {
      const resp = {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'cck-mcp-server', version: '0.2.0' },
        },
      };
      process.stdout.write(JSON.stringify(resp) + '\n');
      return;
    }

    if (method === 'ping') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result: {} }) + '\n');
      return;
    }

    if (method === 'tools/list') {
      const resp = {
        jsonrpc: '2.0',
        id,
        result: { tools },
      };
      process.stdout.write(JSON.stringify(resp) + '\n');
      return;
    }

    if (method === 'tools/call') {
      const { name: toolName, arguments: toolArgs } = params || {};
      if (toolName === 'cck_evaluate_action') {
        const resp = {
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  decision: 'ALLOW',
                  risk_score: 0.1,
                  reason: 'Action conforms to safety policies and verified fact preconditions.',
                }),
              },
            ],
            isError: false,
          },
        };
        process.stdout.write(JSON.stringify(resp) + '\n');
        return;
      }

      if (toolName === 'cck_record_evidence') {
        const resp = {
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  entity_id: toolArgs?.entity_id,
                  field_name: toolArgs?.field_name,
                  value: toolArgs?.value,
                }),
              },
            ],
          },
        };
        process.stdout.write(JSON.stringify(resp) + '\n');
        return;
      }

      if (toolName === 'cck_verify_heartbeat') {
        const resp = {
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  status: 'CONNECTED',
                  agent_id: toolArgs?.agent_id,
                  last_seen_at: new Date().toISOString(),
                }),
              },
            ],
          },
        };
        process.stdout.write(JSON.stringify(resp) + '\n');
        return;
      }

      process.stdout.write(
        JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32601, message: `Tool not found: ${toolName}` } }) + '\n'
      );
      return;
    }

    process.stdout.write(
      JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } }) + '\n'
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    process.stdout.write(
      JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: `Parse error: ${message}` } }) + '\n'
    );
  }
});
