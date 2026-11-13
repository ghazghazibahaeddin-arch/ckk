import { initializeApp, getApps, getApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut as fbSignOut,
  onAuthStateChanged,
  User as FirebaseUser,
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  getDoc,
  setDoc,
  deleteDoc,
  collection,
  query,
  where,
  getDocs,
  getDocFromServer,
} from 'firebase/firestore';
import config from '../firebase-applet-config.json';

const app = getApps().length > 0 ? getApp() : initializeApp(config);
export const auth = getAuth(app);
export const db = config.firestoreDatabaseId
  ? getFirestore(app, config.firestoreDatabaseId)
  : getFirestore(app);
export const googleProvider = new GoogleAuthProvider();

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null) {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

export async function signInWithGoogle() {
  try {
    const result = await signInWithPopup(auth, googleProvider);
    return result.user;
  } catch (err) {
    console.error('Google sign-in error:', err);
    throw err;
  }
}

export async function signOutUser() {
  await fbSignOut(auth);
}

export function subscribeToAuth(callback: (user: FirebaseUser | null) => void) {
  return onAuthStateChanged(auth, callback);
}

function sanitizeId(id: string): string {
  return String(id || '')
    .replace(/[^a-zA-Z0-9_\-]/g, '_')
    .slice(0, 128);
}

export async function syncUserProfile(user: FirebaseUser) {
  const safeUid = sanitizeId(user.uid);
  const userRef = doc(db, 'users', safeUid);
  try {
    const snap = await getDoc(userRef);
    if (!snap.exists()) {
      const newProfile = {
        id: safeUid,
        uid: safeUid,
        email: (user.email || 'user@cck.local').slice(0, 254),
        displayName: (user.displayName || user.email?.split('@')[0] || 'CCK Engineer').slice(0, 120),
        role: 'developer',
        tenant_id: `tenant_${safeUid}`,
        created_at: new Date().toISOString(),
      };
      await setDoc(userRef, newProfile);
      return newProfile;
    }
    return snap.data();
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `users/${safeUid}`);
  }
}

export async function saveUserProject(projectId: string, projectData: Record<string, unknown>) {
  const user = auth.currentUser;
  if (!user) return;
  const safeId = sanitizeId(projectId);
  try {
    const existingSnap = await getDoc(doc(db, 'projects', safeId));
    const createdAt = existingSnap.exists()
      ? (existingSnap.data().created_at as string)
      : (projectData.created_at as string) || new Date().toISOString();

    await setDoc(doc(db, 'projects', safeId), {
      project_id: safeId,
      owner_uid: user.uid,
      tenant_id: String(projectData.tenant_id || `tenant_${user.uid}`).slice(0, 140),
      name: String(projectData.name || 'CCK Project').slice(0, 100),
      description: String(projectData.description || '').slice(0, 500),
      rate_limit_per_minute: Number(projectData.rate_limit_per_minute || 1000),
      created_at: createdAt,
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `projects/${safeId}`);
  }
}

export async function deleteUserProjectDoc(projectId: string) {
  const user = auth.currentUser;
  if (!user) return;
  const safeId = sanitizeId(projectId);
  try {
    await deleteDoc(doc(db, 'projects', safeId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, `projects/${safeId}`);
  }
}

export async function saveUserAgent(agentId: string, agentData: Record<string, unknown>) {
  const user = auth.currentUser;
  if (!user) return;
  const safeId = sanitizeId(agentId);
  try {
    const existingSnap = await getDoc(doc(db, 'agents', safeId));
    const createdAt = existingSnap.exists()
      ? (existingSnap.data().created_at as string)
      : (agentData.created_at as string) || new Date().toISOString();

    await setDoc(doc(db, 'agents', safeId), {
      agent_id: safeId,
      owner_uid: user.uid,
      project_id: sanitizeId(String(agentData.project_id || 'proj-default')),
      tenant_id: String(agentData.tenant_id || `tenant_${user.uid}`).slice(0, 140),
      name: String(agentData.name || 'Agent').slice(0, 120),
      framework: String(agentData.framework || 'langgraph').slice(0, 64),
      target_capability: String(agentData.target_capability || 'orders.refund').slice(0, 120),
      target_resource: String(agentData.target_resource || '*').slice(0, 256),
      guardrail_mode: String(agentData.guardrail_mode || 'ENFORCE_AND_BLOCK').slice(0, 64),
      freshness_ttl_seconds: Number(agentData.freshness_ttl_seconds || 300),
      status: String(agentData.status || 'DISCONNECTED'),
      total_evaluations: Number(agentData.total_evaluations || 0),
      blocked_evaluations: Number(agentData.blocked_evaluations || 0),
      last_seen_at: String(agentData.last_seen_at || ''),
      created_at: createdAt,
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `agents/${safeId}`);
  }
}

export async function deleteUserAgentDoc(agentId: string) {
  const user = auth.currentUser;
  if (!user) return;
  const safeId = sanitizeId(agentId);
  try {
    await deleteDoc(doc(db, 'agents', safeId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, `agents/${safeId}`);
  }
}

export async function saveDecisionReceipt(receiptId: string, receiptData: Record<string, unknown>) {
  const user = auth.currentUser;
  if (!user) return;
  const safeId = sanitizeId(receiptId);
  try {
    await setDoc(doc(db, 'receipts', safeId), {
      receipt_id: safeId,
      owner_uid: user.uid,
      action_id: sanitizeId(String(receiptData.action_id || 'act-unknown')),
      agent_id: sanitizeId(String(receiptData.agent_id || 'agt-unknown')),
      project_id: sanitizeId(String(receiptData.project_id || 'proj-default')),
      tenant_id: String(receiptData.tenant_id || `tenant_${user.uid}`).slice(0, 140),
      status: String(receiptData.status || receiptData.decision || 'BLOCK').slice(0, 32),
      verdict: receiptData.verdict || { decision: receiptData.decision || 'BLOCK', reasoning: String(receiptData.reason || '') },
      timestamp: String(receiptData.timestamp || new Date().toISOString()).slice(0, 64),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `receipts/${safeId}`);
  }
}

export async function loadUserWorkspaceFromFirestore(uid: string): Promise<{
  projects: Record<string, unknown>[];
  agents: Record<string, unknown>[];
  receipts: Record<string, unknown>[];
}> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) {
    return { projects: [], agents: [], receipts: [] };
  }
  try {
    const [projSnap, agentSnap, receiptSnap] = await Promise.all([
      getDocs(query(collection(db, 'projects'), where('owner_uid', '==', uid))),
      getDocs(query(collection(db, 'agents'), where('owner_uid', '==', uid))),
      getDocs(query(collection(db, 'receipts'), where('owner_uid', '==', uid))),
    ]);
    return {
      projects: projSnap.docs.map((d) => d.data()),
      agents: agentSnap.docs.map((d) => d.data()),
      receipts: receiptSnap.docs.map((d) => d.data()),
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, `users/${uid}/workspace`);
    return { projects: [], agents: [], receipts: [] };
  }
}

// Connectivity test
export async function testFirestoreConnection(): Promise<boolean> {
  try {
    await getDocFromServer(doc(db, 'system', 'connection_probe'));
    return true;
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.warn('Firestore is running in offline mode.');
      return false;
    }
    // Document not existing or reachable response means server is online
    return true;
  }
}
