import createClient from "openapi-fetch";
import type { paths } from "./schema";

/**
 * Same-origin base URL. In dev, Vite proxies `/api`, `/hubs`, and
 * `/openapi` to the .NET backend on 127.0.0.1:7070.
 */
export const apiClient = createClient<paths>({ baseUrl: "" });
