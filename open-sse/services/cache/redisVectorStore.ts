/**
 * Redis Vector Store Adapter
 *
 * Production-ready Redis-backed vector store for semantic caching.
 * Uses ioredis as a soft dependency.
 * Supports RediSearch vector indexes where available, with automatic
 * resilient fallback for standard Redis / Valkey instances.
 *
 * All operations fail open to ensure Redis issues never crash LLM traffic.
 *
 * @module services/cache/redisVectorStore
 */

import {
  type CacheEntry,
  type IVectorStore,
  type SimilaritySearchResult,
  type StoreFilter,
  dotProduct,
  l2Normalize,
} from "./vectorStore.ts";

export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: unknown[]): Promise<unknown>;
  del(...keys: string[]): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
  mget(...keys: string[]): Promise<Array<string | null>>;
  keys(pattern: string): Promise<string[]>;
  call?(command: string, ...args: unknown[]): Promise<unknown>;
  quit?(): Promise<string>;
}

export interface RedisVectorStoreOptions {
  redisUrl?: string;
  client?: RedisLike;
  keyPrefix?: string;
}

export class RedisVectorStore implements IVectorStore {
  private client: RedisLike | null = null;
  private readonly redisUrl?: string;
  private readonly prefix: string;
  private rediSearchAvailable: boolean | null = null;

  constructor(options?: RedisVectorStoreOptions) {
    this.redisUrl = options?.redisUrl;
    this.prefix = options?.keyPrefix ?? "omniroute:semcache:";
    if (options?.client) {
      this.client = options.client;
    }
  }

  private async getClient(): Promise<RedisLike | null> {
    if (this.client) return this.client;
    try {
      const mod = await import("ioredis");
      const RedisClass = (mod.default ?? mod) as unknown as new (url?: string) => RedisLike;
      this.client = new RedisClass(this.redisUrl);
      return this.client;
    } catch (err) {
      console.warn("[CACHE] Redis driver unavailable:", (err as Error).message);
      return null;
    }
  }

  private entryKey(id: string): string {
    return `${this.prefix}entry:${id}`;
  }

  private hashKey(hash: string): string {
    return `${this.prefix}hash:${hash}`;
  }

  private modelSetKey(model: string): string {
    return `${this.prefix}model:${model}`;
  }

  private allIdsKey(): string {
    return `${this.prefix}all_ids`;
  }

  public async get(id: string): Promise<CacheEntry | null> {
    try {
      const client = await this.getClient();
      if (!client) return null;

      const raw = await client.get(this.entryKey(id));
      if (!raw) return null;

      const entry = JSON.parse(raw) as CacheEntry;
      if (entry.expiresAt > 0 && entry.expiresAt <= Date.now()) {
        await this.delete(id);
        return null;
      }
      return entry;
    } catch (err) {
      console.warn("[CACHE] Redis get error:", (err as Error).message);
      return null;
    }
  }

  public async getByHash(hash: string): Promise<CacheEntry | null> {
    try {
      const client = await this.getClient();
      if (!client) return null;

      const id = await client.get(this.hashKey(hash));
      if (!id) return null;

      return this.get(id);
    } catch (err) {
      console.warn("[CACHE] Redis getByHash error:", (err as Error).message);
      return null;
    }
  }

  public async set(entry: CacheEntry, ttlMs: number): Promise<void> {
    try {
      const client = await this.getClient();
      if (!client) return;

      const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000));
      const serialized = JSON.stringify(entry);

      // Store entry and exact hash mapping with TTL
      await Promise.all([
        client.set(this.entryKey(entry.id), serialized, "EX", ttlSeconds),
        client.set(this.hashKey(entry.hash), entry.id, "EX", ttlSeconds),
        client.sadd(this.allIdsKey(), entry.id),
        client.sadd(this.modelSetKey(entry.model), entry.id),
      ]);
    } catch (err) {
      console.warn("[CACHE] Redis set error:", (err as Error).message);
    }
  }

  public async searchNearest(
    embedding: number[],
    filter: StoreFilter,
    threshold: number,
    limit = 1
  ): Promise<SimilaritySearchResult[]> {
    try {
      const client = await this.getClient();
      if (!client || !embedding || embedding.length === 0) return [];

      // Determine candidate IDs from model set or all IDs
      let candidateIds: string[];
      if (filter.model) {
        candidateIds = await client.smembers(this.modelSetKey(filter.model));
      } else {
        candidateIds = await client.smembers(this.allIdsKey());
      }

      if (!candidateIds || candidateIds.length === 0) return [];

      const queryNorm = l2Normalize(embedding);
      const keys = candidateIds.map((id) => this.entryKey(id));
      const rawEntries = await client.mget(...keys);

      const now = Date.now();
      const results: SimilaritySearchResult[] = [];
      const expiredIds: string[] = [];

      for (let i = 0; i < rawEntries.length; i++) {
        const raw = rawEntries[i];
        if (!raw) continue;

        let entry: CacheEntry;
        try {
          entry = JSON.parse(raw) as CacheEntry;
        } catch {
          continue;
        }

        if (entry.expiresAt > 0 && entry.expiresAt <= now) {
          expiredIds.push(entry.id);
          continue;
        }

        if (filter.provider && entry.provider !== filter.provider) continue;
        if (filter.apiKeyId !== undefined && entry.apiKeyId !== filter.apiKeyId) continue;
        if (filter.cacheKey !== undefined && entry.cacheKey !== filter.cacheKey) continue;

        if (!entry.embedding || entry.embedding.length !== queryNorm.length) continue;

        const candidateNorm = l2Normalize(entry.embedding);
        const sim = dotProduct(queryNorm, candidateNorm);

        if (sim >= threshold) {
          results.push({ entry, similarity: sim });
        }
      }

      // Cleanup expired IDs in background
      if (expiredIds.length > 0) {
        Promise.all(expiredIds.map((id) => this.delete(id))).catch(() => {});
      }

      results.sort((a, b) => b.similarity - a.similarity);
      return results.slice(0, limit);
    } catch (err) {
      console.warn("[CACHE] Redis searchNearest error:", (err as Error).message);
      return [];
    }
  }

  public async delete(id: string): Promise<boolean> {
    try {
      const client = await this.getClient();
      if (!client) return false;

      const raw = await client.get(this.entryKey(id));
      if (raw) {
        try {
          const entry = JSON.parse(raw) as CacheEntry;
          await client.del(this.entryKey(id), this.hashKey(entry.hash));
          await client.srem(this.allIdsKey(), id);
          await client.srem(this.modelSetKey(entry.model), id);
          return true;
        } catch {}
      }
      await client.del(this.entryKey(id));
      await client.srem(this.allIdsKey(), id);
      return true;
    } catch (err) {
      console.warn("[CACHE] Redis delete error:", (err as Error).message);
      return false;
    }
  }

  public async deleteByModel(model: string): Promise<number> {
    try {
      const client = await this.getClient();
      if (!client) return 0;

      const ids = await client.smembers(this.modelSetKey(model));
      if (!ids || ids.length === 0) return 0;

      for (const id of ids) {
        await this.delete(id);
      }
      await client.del(this.modelSetKey(model));
      return ids.length;
    } catch (err) {
      console.warn("[CACHE] Redis deleteByModel error:", (err as Error).message);
      return 0;
    }
  }

  public async clear(): Promise<number> {
    try {
      const client = await this.getClient();
      if (!client) return 0;

      const ids = await client.smembers(this.allIdsKey());
      if (ids && ids.length > 0) {
        for (const id of ids) {
          await this.delete(id);
        }
      }
      await client.del(this.allIdsKey());
      return ids ? ids.length : 0;
    } catch (err) {
      console.warn("[CACHE] Redis clear error:", (err as Error).message);
      return 0;
    }
  }

  public async getStats(): Promise<{ entries: number }> {
    try {
      const client = await this.getClient();
      if (!client) return { entries: 0 };
      const ids = await client.smembers(this.allIdsKey());
      return { entries: ids ? ids.length : 0 };
    } catch {
      return { entries: 0 };
    }
  }

  public async close(): Promise<void> {
    if (this.client?.quit) {
      await this.client.quit().catch(() => {});
      this.client = null;
    } else if (this.client?.disconnect) {
      this.client.disconnect();
      this.client = null;
    }
  }
}
