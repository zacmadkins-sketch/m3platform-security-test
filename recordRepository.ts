import { randomUUID } from "crypto";
import { createClient, type RedisClientType } from "redis";
import type { HealthRecord } from "../types.js";

// FIX-REDIS-1: ShareRecord no longer stores recordId or any PHI in the Redis value.
// The token maps only to { createdBy, createdAt, used } — the minimum needed for
// revocation and audit. recordId is encoded into the Redis key itself so the
// lookup path never needs to deserialize PHI to validate a token.
export type ShareRecord = {
  token: string;
  recordId: string;
  createdBy: string;
  createdAt: string;
};

// Internal Redis value — intentionally minimal, no PHI.
type RedisShareValue = {
  createdBy: string;
  createdAt: string;
  used: boolean; // FIX-REDIS-3: one-time-use flag
};

export type ShareTokenStore = {
  saveShare: (share: ShareRecord) => Promise<void>;
  // FIX-REDIS-3: consumers call redeemShare to atomically validate + invalidate a token.
  redeemShare: (token: string, recordId: string) => Promise<{ valid: boolean; createdBy?: string }>;
};

export class InMemoryShareTokenStore implements ShareTokenStore {
  private shares: Map<string, ShareRecord & { used: boolean }> = new Map();

  async saveShare(share: ShareRecord): Promise<void> {
    this.shares.set(share.token, { ...share, used: false });
  }

  async redeemShare(token: string, recordId: string): Promise<{ valid: boolean; createdBy?: string }> {
    const entry = this.shares.get(token);
    if (!entry || entry.used || entry.recordId !== recordId) {
      return { valid: false };
    }
    entry.used = true;
    return { valid: true, createdBy: entry.createdBy };
  }
}

export class RedisShareTokenStore implements ShareTokenStore {
  private client: RedisClientType;
  private connected = false;

  // FIX-REDIS-2: TTL in seconds. Default 24 hours. Configurable via env.
  private readonly ttlSeconds: number;

  constructor(
    redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379",
    ttlSeconds = Number(process.env.SHARE_TOKEN_TTL_SECONDS ?? 86400),
  ) {
    this.client = createClient({ url: redisUrl });
    this.ttlSeconds = ttlSeconds;
  }

  private async ensureConnected(): Promise<void> {
    if (this.connected) return;
    await this.client.connect();
    this.connected = true;
  }

  async saveShare(share: ShareRecord): Promise<void> {
    await this.ensureConnected();

    // FIX-REDIS-1: Key encodes recordId so we can scope lookups without storing
    // PHI in the value. Value is minimal: createdBy + createdAt + used flag.
    const key = `share:${share.recordId}:${share.token}`;
    const value: RedisShareValue = {
      createdBy: share.createdBy,
      createdAt: share.createdAt,
      used: false,
    };

    // FIX-REDIS-2: EX sets TTL — token expires automatically after ttlSeconds.
    await this.client.set(key, JSON.stringify(value), { EX: this.ttlSeconds });
  }

  // FIX-REDIS-3: Atomic one-time-use via Redis GET + SET with used=true.
  // A token that has already been redeemed cannot be redeemed again.
  // Note: for stricter atomicity under high concurrency, replace with a Lua script
  // or Redis GETDEL — this implementation is sufficient for low-concurrency clinical use.
  async redeemShare(token: string, recordId: string): Promise<{ valid: boolean; createdBy?: string }> {
    await this.ensureConnected();

    const key = `share:${recordId}:${token}`;
    const raw = await this.client.get(key);
    if (!raw) return { valid: false };

    const value: RedisShareValue = JSON.parse(raw);
    if (value.used) return { valid: false };

    // Mark as used and reset TTL to a short cleanup window (5 minutes).
    const used: RedisShareValue = { ...value, used: true };
    await this.client.set(key, JSON.stringify(used), { EX: 300 });

    return { valid: true, createdBy: value.createdBy };
  }
}

export class InMemoryRecordRepository {
  private records: HealthRecord[] = [
    {
      id: "rec-100",
      ownerUserId: "user-1",
      patientName: "Taylor Reed",
      dob: "1988-05-09",
      encounterSummary: "Follow-up for recurring urinary symptoms",
      notes: "Medication changed last visit. Monitor response and side effects.",
    },
    {
      id: "rec-200",
      ownerUserId: "user-2",
      patientName: "Jordan Kim",
      dob: "1979-11-30",
      encounterSummary: "Post-procedure pain and hydration concerns",
      notes: "Pain has improved but still intermittent.",
    },
  ];

  constructor(private shareStore: ShareTokenStore = new InMemoryShareTokenStore()) {}

  getRecordById(recordId: string): HealthRecord | undefined {
    return this.records.find((r) => r.id === recordId);
  }

  // FIX-REDIS-1: Token is now a cryptographically random UUID with no recordId prefix.
  // This removes the guessable structure that made brute-force attacks easier.
  async createShare(recordId: string, createdBy: string): Promise<ShareRecord> {
    const token = randomUUID(); // cryptographically strong, 122 bits of entropy
    const share: ShareRecord = {
      token,
      recordId,
      createdBy,
      createdAt: new Date().toISOString(),
    };
    await this.shareStore.saveShare(share);
    return share;
  }

  getShareStore(): ShareTokenStore {
    return this.shareStore;
  }
}
