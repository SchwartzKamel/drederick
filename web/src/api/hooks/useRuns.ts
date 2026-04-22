import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type {
  EventsBatch,
  RunRecord,
  StartRunRequest,
  StartRunResponse,
} from "../types";

export function useRuns() {
  return useQuery({
    queryKey: ["runs", "list"] as const,
    queryFn: () => api.get<RunRecord[]>("/api/runs"),
    refetchInterval: 5_000,
  });
}

export function useRun(runId: string | null | undefined) {
  return useQuery({
    queryKey: ["runs", "detail", runId] as const,
    enabled: !!runId,
    queryFn: () => api.get<RunRecord>(`/api/runs/${runId}`),
    refetchInterval: 3_000,
  });
}

export function useRunEvents(
  runId: string | null | undefined,
  params?: { since?: string },
) {
  return useQuery({
    queryKey: ["runs", "events", runId, params] as const,
    enabled: !!runId,
    queryFn: () =>
      api.get<EventsBatch>(`/api/runs/${runId}/events`, {
        since: params?.since,
      }),
  });
}

export function useStartRun() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: StartRunRequest) =>
      api.post<StartRunResponse, StartRunRequest>("/api/runs", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useCancelRun() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (runId: string) => api.delete(`/api/runs/${runId}`),
    onSuccess: (_data, runId) => {
      qc.invalidateQueries({ queryKey: ["runs"] });
      qc.invalidateQueries({ queryKey: ["runs", "detail", runId] });
    },
  });
}
