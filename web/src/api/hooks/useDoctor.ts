import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import type { DoctorCheck, DoctorChecksPayload } from "../types";

export function useDoctorChecks() {
  return useQuery({
    queryKey: ["doctor", "checks"] as const,
    queryFn: () => api.get<DoctorChecksPayload>("/api/doctor/checks"),
    refetchInterval: 30_000,
  });
}

export function useDoctorCheck(checkId: string | null | undefined) {
  return useQuery({
    queryKey: ["doctor", "check", checkId] as const,
    enabled: !!checkId,
    queryFn: () => api.get<DoctorCheck>(`/api/doctor/checks/${checkId}`),
  });
}
