import type { ClientHwidInfo } from '@/lib/clients/hwid-log';

export type InboundLimitAuditIp = {
  ip: string;
  time: string;
  node: string;
};

export type InboundLimitAuditHistory = {
  ip: string;
  firstSeen: string;
  lastSeen: string;
};

export type InboundLimitAuditClient = {
  email: string;
  subId: string;
  onlineIps: InboundLimitAuditIp[];
  history: InboundLimitAuditHistory[];
  devices: ClientHwidInfo[];
};

export type InboundLimitAuditRejection = {
  id: number;
  inboundId: number;
  tag: string;
  email: string;
  ip: string;
  action: string;
  createdAt: number;
};

export type InboundLimitAudit = {
  inboundId: number;
  tag: string;
  remark: string;
  limitIp: number;
  limitAction: string;
  onlineIpCount: number;
  remote: boolean;
  clients: InboundLimitAuditClient[];
  rejections: InboundLimitAuditRejection[];
};

// Go 的 nil slice 会序列化成 null，这里把 client 内部的数组也统一兜底。
function normalizeAuditClient(raw: unknown): InboundLimitAuditClient | null {
  if (!raw || typeof raw !== 'object') return null;
  const client = raw as Partial<InboundLimitAuditClient>;
  if (typeof client.email !== 'string') return null;
  return {
    email: client.email,
    subId: typeof client.subId === 'string' ? client.subId : '',
    onlineIps: Array.isArray(client.onlineIps) ? client.onlineIps : [],
    history: Array.isArray(client.history) ? client.history : [],
    devices: Array.isArray(client.devices) ? client.devices : [],
  };
}

function normalizeRejection(raw: unknown): InboundLimitAuditRejection | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Partial<InboundLimitAuditRejection>;
  if (typeof row.id !== 'number') return null;
  return row as InboundLimitAuditRejection;
}

export function normalizeInboundLimitAudit(obj: unknown): InboundLimitAudit | null {
  if (!obj || typeof obj !== 'object') return null;
  const data = obj as Partial<InboundLimitAudit>;
  if (typeof data.inboundId !== 'number') return null;
  return {
    inboundId: data.inboundId,
    tag: typeof data.tag === 'string' ? data.tag : '',
    remark: typeof data.remark === 'string' ? data.remark : '',
    limitIp: typeof data.limitIp === 'number' ? data.limitIp : 0,
    limitAction: typeof data.limitAction === 'string' ? data.limitAction : 'reject_new',
    onlineIpCount: typeof data.onlineIpCount === 'number' ? data.onlineIpCount : 0,
    remote: data.remote === true,
    clients: (Array.isArray(data.clients) ? data.clients : [])
      .map(normalizeAuditClient)
      .filter((row): row is InboundLimitAuditClient => row !== null),
    rejections: (Array.isArray(data.rejections) ? data.rejections : [])
      .map(normalizeRejection)
      .filter((row): row is InboundLimitAuditRejection => row !== null),
  };
}
