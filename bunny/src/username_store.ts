// ABOUTME: Username store abstraction for Bunny Edge Scripting (NIP-05, WebFinger, ATProto DID, profiles).
// ABOUTME: Supports in-memory fixtures (tests/dev), Bunny Database (libSQL HTTP), and divine-name-server HTTP lookup.

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
        void resp.body?.cancel().catch(() => {});
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

/**
 * Reads username routing metadata directly from divine-name-server over HTTP
 * (`GET /api/username/lookup/:name`) with an automatic fallback to
 * `/.well-known/nostr.json?name=:name` if the lookup endpoint is not deployed yet,
 * backed by a bounded in-isolate TTL cache.
 */
export class NameServerUsernameStore implements UsernameStore {
  private readonly cache = new Map<string, { value: UsernameData | null; expiresAt: number }>();

  constructor(
    private readonly baseUrl: string,
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

  private async fallbackNip05Lookup(base: string, key: string, now: number): Promise<UsernameData | null> {
    const resp = await this.fetcher(
      `${base}/.well-known/nostr.json?name=${encodeURIComponent(key)}`,
      {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(this.timeoutMs),
      },
    );
    if (!resp.ok) {
      void resp.body?.cancel().catch(() => {});
      return null;
    }
    const payload = await resp.json() as {
      names?: Record<string, string>;
      relays?: Record<string, string[]>;
    };
    const names = payload?.names;
    if (!names || typeof names !== "object") {
      return null;
    }
    const matchedEntry = Object.entries(names).find(([k]) => k.toLowerCase() === key);
    if (!matchedEntry || typeof matchedEntry[1] !== "string" || matchedEntry[1].length === 0) {
      this.setCache(key, null, now + this.ttlMs);
      return null;
    }
    const pubkey = matchedEntry[1];
    const rawRelays = payload.relays?.[pubkey];
    const relays = Array.isArray(rawRelays)
      ? rawRelays.filter((r): r is string => typeof r === "string")
      : [];
    const record: UsernameData = {
      pubkey,
      relays,
      status: "active",
      atproto_did: null,
      atproto_state: null,
    };
    this.setCache(key, record, now + this.ttlMs);
    return record;
  }

  async lookup(username: string): Promise<UsernameData | null> {
    const key = username.toLowerCase();
    const now = Date.now();
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > now) {
      return cached.value;
    }

    const base = this.baseUrl.replace(/\/$/, "");
    try {
      const resp = await this.fetcher(
        `${base}/api/username/lookup/${encodeURIComponent(key)}`,
        {
          headers: { accept: "application/json" },
          signal: AbortSignal.timeout(this.timeoutMs),
        },
      );

      if (resp.status === 404) {
        const ct = (resp.headers.get("content-type") ?? "").toLowerCase();
        void resp.body?.cancel().catch(() => {});
        if (ct.includes("application/json")) {
          this.setCache(key, null, now + this.ttlMs);
          return null;
        }
        // Non-JSON 404 indicates /api/username/lookup/:name is not yet deployed;
        // fall back to /.well-known/nostr.json for NIP-05/profile routing.
        return await this.fallbackNip05Lookup(base, key, now);
      }

      if (!resp.ok) {
        void resp.body?.cancel().catch(() => {});
        return null;
      }

      const payload = await resp.json() as {
        pubkey?: unknown;
        relays?: unknown;
        status?: unknown;
        atproto_did?: unknown;
        atproto_state?: unknown;
      };
      if (typeof payload.pubkey !== "string" || payload.pubkey.length === 0) {
        return null;
      }
      const relays = Array.isArray(payload.relays)
        ? payload.relays.filter((r): r is string => typeof r === "string")
        : [];
      const record: UsernameData = {
        pubkey: payload.pubkey,
        relays,
        status: typeof payload.status === "string" ? payload.status : "active",
        atproto_did: typeof payload.atproto_did === "string" ? payload.atproto_did : null,
        atproto_state: typeof payload.atproto_state === "string" ? payload.atproto_state : null,
      };
      this.setCache(key, record, now + this.ttlMs);
      return record;
    } catch {
      return null;
    }
  }
}

export function createUsernameStoreFromEnv(): UsernameStore {
  const ttlMsRaw = Number.parseInt(Deno.env.get("USERNAME_CACHE_TTL_MS") ?? "30000", 10);
  const ttlMs = Number.isFinite(ttlMsRaw) && ttlMsRaw >= 0 ? ttlMsRaw : 30_000;

  const dbUrl = Deno.env.get("BUNNY_DB_URL");
  const dbToken = Deno.env.get("BUNNY_DB_TOKEN");
  if (dbUrl && dbToken) {
    return new BunnyDatabaseUsernameStore(dbUrl, dbToken, ttlMs);
  }

  const nameServerUrl = Deno.env.get("NAME_SERVER_URL");
  if (nameServerUrl) {
    return new NameServerUsernameStore(nameServerUrl, ttlMs);
  }

  return new NullUsernameStore();
}
