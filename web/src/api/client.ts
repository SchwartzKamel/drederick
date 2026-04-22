import createClient from "openapi-fetch";
import type { paths } from "./schema";

/**
 * Typed fetch wrapper over the Drederick HTTP surface.
 *
 * Design points:
 *   - Same-origin by default (`baseUrl: ""`) — Vite proxies `/api`,
 *     `/hubs`, `/openapi` to the .NET backend in dev.
 *   - Bearer token is read from `localStorage.drederick_bearer` on
 *     construction and on every request (so `setBearerToken` takes
 *     effect without a reload).
 *   - snake_case JSON bodies: callers pass bodies with the exact field
 *     names the backend expects (see `./types`). This client does NOT
 *     camelCase-convert anything.
 *   - Errors throw `DrederickApiError` with status + parsed body.
 */

const BEARER_KEY = "drederick_bearer";

export function getBearerToken(): string | null {
  if (typeof localStorage === "undefined") return null;
  return localStorage.getItem(BEARER_KEY);
}

export function setBearerToken(token: string | null): void {
  if (typeof localStorage === "undefined") return;
  if (token === null || token === "") {
    localStorage.removeItem(BEARER_KEY);
  } else {
    localStorage.setItem(BEARER_KEY, token);
  }
}

export type DrederickApiConfig = {
  baseUrl: string;
  bearerToken?: string | null;
};

export class DrederickApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly path: string;

  constructor(path: string, status: number, body: unknown, message?: string) {
    super(message ?? `HTTP ${status} on ${path}`);
    this.name = "DrederickApiError";
    this.status = status;
    this.body = body;
    this.path = path;
  }

  get isAuth(): boolean {
    return this.status === 401 || this.status === 403;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }
}

function buildQuery(params?: Record<string, unknown>): string {
  if (!params) return "";
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) {
      for (const item of v) {
        if (item === undefined || item === null) continue;
        usp.append(k, String(item));
      }
    } else {
      usp.append(k, String(v));
    }
  }
  const q = usp.toString();
  return q ? `?${q}` : "";
}

export class DrederickApi {
  private readonly baseUrl: string;
  private tokenOverride: string | null | undefined;

  constructor(cfg?: Partial<DrederickApiConfig>) {
    this.baseUrl = cfg?.baseUrl ?? "";
    this.tokenOverride = cfg?.bearerToken;
  }

  private headers(extra?: HeadersInit): Headers {
    const h = new Headers(extra);
    const token = this.tokenOverride !== undefined ? this.tokenOverride : getBearerToken();
    if (token) h.set("Authorization", `Bearer ${token}`);
    return h;
  }

  private url(path: string, params?: Record<string, unknown>): string {
    return `${this.baseUrl}${path}${buildQuery(params)}`;
  }

  private async request<T>(
    method: string,
    path: string,
    opts: { params?: Record<string, unknown>; body?: unknown } = {},
  ): Promise<T> {
    const headers = this.headers();
    let body: BodyInit | undefined;
    if (opts.body !== undefined && opts.body !== null) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(opts.body);
    }
    let res: Response;
    try {
      res = await fetch(this.url(path, opts.params), { method, headers, body });
    } catch (e) {
      throw new DrederickApiError(path, 0, null,
        e instanceof Error ? `network: ${e.message}` : "network failure");
    }
    if (res.status === 204) {
      return undefined as T;
    }
    const contentType = res.headers.get("content-type") ?? "";
    const isJson = contentType.includes("application/json");
    const parsed = isJson ? await res.json().catch(() => null) : await res.text().catch(() => null);
    if (!res.ok) {
      throw new DrederickApiError(path, res.status, parsed);
    }
    return parsed as T;
  }

  get<T>(path: string, params?: Record<string, unknown>): Promise<T> {
    return this.request<T>("GET", path, { params });
  }

  post<T, B = unknown>(path: string, body?: B): Promise<T> {
    return this.request<T>("POST", path, { body });
  }

  put<T, B = unknown>(path: string, body?: B): Promise<T> {
    return this.request<T>("PUT", path, { body });
  }

  delete(path: string): Promise<void> {
    return this.request<void>("DELETE", path);
  }
}

/** Singleton used by all hooks. */
export const api = new DrederickApi();

/**
 * Backward-compat export for the openapi-fetch typed client used by
 * `HealthIndicator` and the `pnpm generate:api` pipeline. New code
 * should prefer `api` above.
 */
export const apiClient = createClient<paths>({
  baseUrl: "",
  headers: {
    get Authorization() {
      const t = getBearerToken();
      return t ? `Bearer ${t}` : "";
    },
  } as unknown as HeadersInit,
});
