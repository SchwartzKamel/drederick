import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type {
  JeopardyChallengeState,
  JeopardyHintHistory,
  JeopardyHintRequest,
  JeopardyHintResponse,
  JeopardySessionDetail,
  JeopardySessionSummary,
  JeopardyStartRequest,
  JeopardyStartResponse,
} from "../types";

export function useJeopardySessions() {
  return useQuery({
    queryKey: ["jeopardy", "sessions"] as const,
    queryFn: () => api.get<JeopardySessionSummary[]>("/api/jeopardy/sessions"),
    refetchInterval: 5_000,
  });
}

export function useJeopardySession(sessionId: string | null | undefined) {
  return useQuery({
    queryKey: ["jeopardy", "session", sessionId] as const,
    enabled: !!sessionId,
    queryFn: () =>
      api.get<JeopardySessionDetail>(`/api/jeopardy/sessions/${sessionId}`),
    refetchInterval: 3_000,
  });
}

export function useJeopardyChallenges(sessionId: string | null | undefined) {
  return useQuery({
    queryKey: ["jeopardy", "challenges", sessionId] as const,
    enabled: !!sessionId,
    queryFn: () =>
      api.get<JeopardyChallengeState[]>(
        `/api/jeopardy/sessions/${sessionId}/challenges`,
      ),
  });
}

export function useJeopardyChallenge(
  sessionId: string | null | undefined,
  challengeId: number | null | undefined,
) {
  return useQuery({
    queryKey: ["jeopardy", "challenge", sessionId, challengeId] as const,
    enabled: !!sessionId && challengeId !== null && challengeId !== undefined,
    queryFn: () =>
      api.get<JeopardyChallengeState>(
        `/api/jeopardy/sessions/${sessionId}/challenges/${challengeId}`,
      ),
  });
}

export function useJeopardySwarm(sessionId: string | null | undefined) {
  return useQuery({
    queryKey: ["jeopardy", "swarm", sessionId] as const,
    enabled: !!sessionId,
    queryFn: () =>
      api.get<JeopardyChallengeState[]>(
        `/api/jeopardy/sessions/${sessionId}/swarm`,
      ),
    refetchInterval: 2_000,
  });
}

export function useJeopardyHints(sessionId: string | null | undefined) {
  return useQuery({
    queryKey: ["jeopardy", "hints", sessionId] as const,
    enabled: !!sessionId,
    queryFn: () =>
      api.get<JeopardyHintHistory[]>(
        `/api/jeopardy/sessions/${sessionId}/hints`,
      ),
  });
}

export function useStartJeopardySession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: JeopardyStartRequest) =>
      api.post<JeopardyStartResponse, JeopardyStartRequest>(
        "/api/jeopardy/sessions",
        body,
      ),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["jeopardy", "sessions"] }),
  });
}

export function useCancelJeopardySession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (sessionId: string) =>
      api.delete(`/api/jeopardy/sessions/${sessionId}`),
    onSuccess: (_data, sessionId) => {
      qc.invalidateQueries({ queryKey: ["jeopardy", "sessions"] });
      qc.invalidateQueries({ queryKey: ["jeopardy", "session", sessionId] });
    },
  });
}

export function usePostJeopardyHint(sessionId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: JeopardyHintRequest) =>
      api.post<JeopardyHintResponse, JeopardyHintRequest>(
        `/api/jeopardy/sessions/${sessionId}/hints`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["jeopardy", "hints", sessionId] });
      qc.invalidateQueries({ queryKey: ["jeopardy", "swarm", sessionId] });
    },
  });
}
