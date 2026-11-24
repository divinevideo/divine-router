// ABOUTME: Username store abstraction for Bunny Edge Scripting (NIP-05, WebFinger, ATProto DID, profiles).
// ABOUTME: Supports in-memory fixtures (tests/dev) and Bunny Database over the libSQL HTTP pipeline API.

import type { UsernameData } from "./router.ts";

export interface UsernameStore {
  lookup(username: string): Promise<UsernameData | null>;
}

/**
 * Looks up a username with the same defensive dotless fallback as src/main.rs
 * (handles legacy dotted names like lele.pons -> lelepons).
 */
export async function lookupUsernameWithFallback(
  store: UsernameStore,
  username: string,
): Promise<UsernameData | null> {
  const exact = await store.lookup(username);
  if (exact) {
    return exact;
  }

  if (username.includes(".")) {
    const dotless = username.replaceAll(".", "");
    if (dotless.length > 0) {
      return await store.lookup(dotless);
    }
  }

  return null;
}

export class NullUsernameStore implements UsernameStore {
  lookup(_username: string): Promise<UsernameData | null> {
    return Promise.resolve(null);
  }
}

/**
 * In-memory store compatible with Fastly's kv_usernames.json fixture format
 * (`{ "alice": { "data": "{...}" } }`) or direct `{ "user:alice": UsernameData }`.
 */
export class MemoryUsernameStore implements UsernameStore {
  private readonly records: Map<string, UsernameData>;

  constructor(entries: Record<string, UsernameData | { data: string }>) {
    this.records = new Map();
    for (const [rawKey, value] of Object.entries(entries)) {
      const normalizedKey = rawKey.startsWith("user:")
        ? rawKey.slice("user:".length).toLowerCase()
        : rawKey.toLowerCase();
      if ("data" in value && typeof value.data === "string") {
        try {
          this.records.set(normalizedKey, JSON.parse(value.data) as UsernameData);
        } catch {
          // Ignore malformed fixture entry
        }
      } else {
        this.records.set(normalizedKey, value as UsernameData);
      }
    }
  }

  lookup(username: string): Promise<UsernameData | null> {
    return Promise.resolve(this.records.get(username.toLowerCase()) ?? null);
  }
}

/**
 * Reads username records from a Bunny Database (libSQL Hrana HTTP pipeline API)
 * with a short in-isolate TTL cache to avoid repeated round trips on hot handles.
 *
 * Expected table schema:
 *   CREATE TABLE IF NOT EXISTS usernames (
 *     username TEXT PRIMARY KEY,
 *     pubkey TEXT NOT NULL,
 *     relays_json TEXT NOT NULL DEFAULT '[]',
 *     status TEXT NOT NULL DEFAULT 'active',
 *     atproto_did TEXT,
 *     atproto_state TEXT
 *   );
 */
export class BunnyDatabaseUsernameStore implements UsernameStore {
  private readonly cache = new Map<string, { value: UsernameData | null; expiresAt: number }>();

  constructor(
    private readonly dbUrl: string,
    private readonly authToken: string,
    private readonly ttlMs = 30_000,
    private readonly fetcher: typeof fetch = fetch,
    private readonly maxCacheEntries = 10_000,
    private readonly timeoutMs = 5_000,
  ) {}

  private setCache(key: string, value: UsernameData | null, expiresAt: number): void {
    if (this.cache.size >= this.maxCacheEntries && !this.cache.has(key)) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }
    this.cache.set(key, { value, expiresAt });
  }

  async lookup(username: string): Promise<UsernameData | null> {
    const key = username.toLowerCase();
    const now = Date.now();
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > now) {
      return cached.value;
    }

    const endpoint = `${this.dbUrl.replace(/\/$/, "")}/v2/pipeline`;
    try {
      const resp = await this.fetcher(endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.authToken}`,
        },
        signal: AbortSignal.timeout(this.timeoutMs),
        body: JSON.stringify({
          requests: [
            {
              type: "execute",
              stmt: {
                sql: "SELECT pubkey, relays_json, status, atproto_did, atproto_state FROM usernames WHERE username = ? LIMIT 1",
                args: [{ type: "text", value: key }],
              },
            },
            { type: "close" },
          ],
        }),
      });

      if (!resp.ok) {
        return null;
      }

      const payload = await resp.json() as {
        results?: Array<{
          type?: string;
          response?: {
            result?: {
              rows?: Array<Array<{ value?: string | null }>>;
            };
          };
        }>;
      };

      const firstResult = payload.results?.[0];
      const rows = firstResult?.response?.result?.rows;
      // libSQL Hrana returns HTTP 200 for per-statement SQL errors ({ type: "error" }).
      // Never cache transient statement/schema errors as negative lookups.
      if (!firstResult || (firstResult.type && firstResult.type !== "ok") || !Array.isArray(rows)) {
        return null;
      }

      const row = rows[0];
      if (!row || !row[0]?.value) {
        this.setCache(key, null, now + this.ttlMs);
        return null;
      }

      let relays: string[] = [];
      if (row[1]?.value) {
        try {
          const parsed = JSON.parse(row[1].value);
          if (Array.isArray(parsed)) {
            relays = parsed.filter((r): r is string => typeof r === "string");
          }
        } catch {
          relays = [];
        }
      }

      const record: UsernameData = {
        pubkey: row[0].value,
        relays,
        status: row[2]?.value ?? "",
        atproto_did: row[3]?.value ?? null,
        atproto_state: row[4]?.value ?? null,
      };
      this.setCache(key, record, now + this.ttlMs);
      return record;
    } catch {
      return null;
    }
  }
}

export function createUsernameStoreFromEnv(): UsernameStore {
  const dbUrl = Deno.env.get("BUNNY_DB_URL");
  const dbToken = Deno.env.get("BUNNY_DB_TOKEN");
  if (dbUrl && dbToken) {
    const ttlMs = Number.parseInt(Deno.env.get("USERNAME_CACHE_TTL_MS") ?? "30000", 10);
    return new BunnyDatabaseUsernameStore(
      dbUrl,
      dbToken,
      Number.isFinite(ttlMs) && ttlMs >= 0 ? ttlMs : 30_000,
    );
  }
  return new NullUsernameStore();
}
