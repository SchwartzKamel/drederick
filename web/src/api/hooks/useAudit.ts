import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import type { AuditCategoriesResponse, AuditTailResponse } from "../types";

export function useAuditTail(params?: {
  since?: string;
  limit?: number;
  category?: string;
}) {
  return useQuery({
    queryKey: ["audit", "tail", params] as const,
    queryFn: () =>
      api.get<AuditTailResponse>("/api/audit/tail", {
        since: params?.since,
        limit: params?.limit,
        category: params?.category,
      }),
    refetchInterval: 5_000,
  });
}

export function useAuditCategories() {
  return useQuery({
    queryKey: ["audit", "categories"] as const,
    queryFn: () => api.get<AuditCategoriesResponse>("/api/audit/categories"),
    staleTime: 60_000,
  });
}
