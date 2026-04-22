import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import type {
  CveDetail,
  CveRow,
  ExploitRunRow,
  FindingsSummary,
  GenericFindingRow,
  HostDetail,
  HostFindingRow,
  LootRow,
  MaybeNoDb,
  PagedResponse,
  PocRefRow,
  ServiceDetail,
  ServiceRow,
  SessionRow,
  Severity,
} from "../types";

type PageParams = { limit?: number; offset?: number };

export function useHosts(params?: { q?: string } & PageParams) {
  return useQuery({
    queryKey: ["findings", "hosts", params] as const,
    queryFn: () =>
      api.get<MaybeNoDb<PagedResponse<HostFindingRow>>>(
        "/api/findings/hosts",
        { q: params?.q, limit: params?.limit, offset: params?.offset },
      ),
  });
}

export function useHost(hostId: number | null | undefined) {
  return useQuery({
    queryKey: ["findings", "host", hostId] as const,
    enabled: hostId !== null && hostId !== undefined,
    queryFn: () => api.get<MaybeNoDb<HostDetail>>(`/api/findings/hosts/${hostId}`),
  });
}

export function useServices(params?: { host_id?: number } & PageParams) {
  return useQuery({
    queryKey: ["findings", "services", params] as const,
    queryFn: () =>
      api.get<MaybeNoDb<PagedResponse<ServiceRow>>>("/api/findings/services", {
        host_id: params?.host_id,
        limit: params?.limit,
        offset: params?.offset,
      }),
  });
}

export function useService(serviceId: number | null | undefined) {
  return useQuery({
    queryKey: ["findings", "service", serviceId] as const,
    enabled: serviceId !== null && serviceId !== undefined,
    queryFn: () =>
      api.get<MaybeNoDb<ServiceDetail>>(`/api/findings/services/${serviceId}`),
  });
}

export function useCves(
  params?: {
    host_id?: number;
    service_id?: number;
    severity?: Severity;
  } & PageParams,
) {
  return useQuery({
    queryKey: ["findings", "cves", params] as const,
    queryFn: () =>
      api.get<MaybeNoDb<PagedResponse<CveRow>>>("/api/findings/cves", {
        host_id: params?.host_id,
        service_id: params?.service_id,
        severity: params?.severity,
        limit: params?.limit,
        offset: params?.offset,
      }),
  });
}

export function useCve(cveId: string | null | undefined) {
  return useQuery({
    queryKey: ["findings", "cve", cveId] as const,
    enabled: !!cveId,
    queryFn: () =>
      api.get<MaybeNoDb<CveDetail>>(
        `/api/findings/cves/${encodeURIComponent(cveId!)}`,
      ),
  });
}

export function usePocRefs(
  params?: {
    cve_id?: string;
    source?: string;
    match_confidence?: string;
  } & PageParams,
) {
  return useQuery({
    queryKey: ["findings", "poc_refs", params] as const,
    queryFn: () =>
      api.get<MaybeNoDb<PagedResponse<PocRefRow>>>("/api/findings/poc-refs", {
        cve_id: params?.cve_id,
        source: params?.source,
        match_confidence: params?.match_confidence,
        limit: params?.limit,
        offset: params?.offset,
      }),
  });
}

export function useExploitRuns(
  params?: { target?: string; tool?: string; category?: string } & PageParams,
) {
  return useQuery({
    queryKey: ["findings", "exploit_runs", params] as const,
    queryFn: () =>
      api.get<MaybeNoDb<PagedResponse<ExploitRunRow>>>(
        "/api/findings/exploit-runs",
        {
          target: params?.target,
          tool: params?.tool,
          category: params?.category,
          limit: params?.limit,
          offset: params?.offset,
        },
      ),
  });
}

export function useSessionRows(
  params?: {
    target?: string;
    protocol?: string;
    state?: "open" | "closed";
  } & PageParams,
) {
  return useQuery({
    queryKey: ["findings", "sessions", params] as const,
    queryFn: () =>
      api.get<MaybeNoDb<PagedResponse<SessionRow>>>("/api/findings/sessions", {
        target: params?.target,
        protocol: params?.protocol,
        state: params?.state,
        limit: params?.limit,
        offset: params?.offset,
      }),
  });
}

export function useLoot(params?: { target?: string; kind?: string } & PageParams) {
  return useQuery({
    queryKey: ["findings", "loot", params] as const,
    queryFn: () =>
      api.get<MaybeNoDb<PagedResponse<LootRow>>>("/api/findings/loot", {
        target: params?.target,
        kind: params?.kind,
        limit: params?.limit,
        offset: params?.offset,
      }),
  });
}

export function useFindingsList(params?: { host_id?: number } & PageParams) {
  return useQuery({
    queryKey: ["findings", "list", params] as const,
    queryFn: () =>
      api.get<MaybeNoDb<PagedResponse<GenericFindingRow>>>("/api/findings/", {
        host_id: params?.host_id,
        limit: params?.limit,
        offset: params?.offset,
      }),
  });
}

export function useFindingsSummary() {
  return useQuery({
    queryKey: ["findings", "summary"] as const,
    queryFn: () => api.get<MaybeNoDb<FindingsSummary>>("/api/findings/summary"),
  });
}
