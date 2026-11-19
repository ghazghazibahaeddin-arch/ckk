export interface TenantTestSession {
  token: string;
  tenantId: string;
  projectId: string;
  user: Record<string, any>;
  headers: Record<string, string>;
}

export function authHeaders(token: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
    ...extra,
  };
}

export async function waitForServer(baseUrl = 'http://localhost:3000'): Promise<void> {
  for (let i = 0; i < 20; i++) {
    try {
      const res = await fetch(`${baseUrl}/health`);
      if (res.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`Server at ${baseUrl} did not respond to /health`);
}

export async function createTenantSession(
  baseUrl = 'http://localhost:3000',
  prefix = 'test'
): Promise<TenantTestSession> {
  await waitForServer(baseUrl);
  const rand = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const username = `${prefix}_${rand}`.toLowerCase();
  const email = `${username}@example.com`;
  const res = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      email,
      password: `TestPass!${rand}`,
      display_name: `Test User ${prefix}`,
    }),
  });
  const data = await res.json();
  if (!res.ok || !data?.token) {
    throw new Error(`createTenantSession failed [${res.status}]: ${JSON.stringify(data)}`);
  }
  return {
    token: data.token,
    tenantId: data.user.tenant_id,
    projectId: data.starter_project?.project_id || data.project?.project_id || '',
    user: data.user,
    headers: authHeaders(data.token),
  };
}

export async function createMemberSession(
  baseUrl: string,
  supervisorToken: string,
  role: 'viewer' | 'operator' | 'supervisor' | 'developer',
  prefix = 'member'
): Promise<{ token: string; user: Record<string, any>; headers: Record<string, string> }> {
  const rand = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const username = `${prefix}_${role}_${rand}`.toLowerCase();
  const res = await fetch(`${baseUrl}/api/v1/auth/members`, {
    method: 'POST',
    headers: authHeaders(supervisorToken),
    body: JSON.stringify({
      username,
      password: `MemberPass!${rand}`,
      display_name: `Member ${role} ${rand}`,
      role,
    }),
  });
  const data = await res.json();
  if (!res.ok || !data?.token) {
    throw new Error(`createMemberSession failed [${res.status}]: ${JSON.stringify(data)}`);
  }
  return {
    token: data.token,
    user: data.user,
    headers: authHeaders(data.token),
  };
}

export async function mintProjectApiKey(
  baseUrl: string,
  sessionToken: string,
  projectId: string,
  name = 'Test Key'
): Promise<{ keyId: string; token: string }> {
  const res = await fetch(`${baseUrl}/api/v1/projects/${projectId}/keys`, {
    method: 'POST',
    headers: authHeaders(sessionToken),
    body: JSON.stringify({ name }),
  });
  const data = await res.json();
  if (!res.ok || !data?.token) {
    throw new Error(`mintProjectApiKey failed [${res.status}]: ${JSON.stringify(data)}`);
  }
  return { keyId: data.key_id, token: data.token };
}
