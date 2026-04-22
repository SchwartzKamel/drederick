import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../client";
import type {
  ScopeValidateRequest,
  ScopeValidateResponse,
  ScopeViewResponse,
} from "../types";

export function useScope(path: string | null | undefined) {
  return useQuery({
    queryKey: ["scope", "view", path] as const,
    enabled: !!path,
    queryFn: () => api.get<ScopeViewResponse>("/api/scope", { path }),
  });
}

export function useValidateScope() {
  return useMutation({
    mutationFn: (body: ScopeValidateRequest) =>
      api.post<ScopeValidateResponse, ScopeValidateRequest>(
        "/api/scope/validate",
        body,
      ),
  });
}
