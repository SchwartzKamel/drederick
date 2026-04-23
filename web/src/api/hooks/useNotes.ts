import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type {
  CreateNoteRequest,
  MaybeNoDb,
  Note,
  NotesListResponse,
} from "../types";

/**
 * TanStack Query hooks for `/api/notes`. Mirrors `useFindings.ts` shape.
 * Notes are operator-authored prose; the list endpoint returns the
 * `no_database` stand-in when `findings.db` is absent, so callers
 * should branch on `isNoDatabase` before reading `.notes`.
 */

export function useNotes(params?: { host?: string; tag?: string }) {
  return useQuery({
    queryKey: ["notes", "list", params] as const,
    queryFn: () =>
      api.get<MaybeNoDb<NotesListResponse>>("/api/notes", {
        host: params?.host,
        tag: params?.tag,
      }),
  });
}

export function useNote(id: number | null | undefined) {
  return useQuery({
    queryKey: ["notes", "detail", id] as const,
    enabled: id !== null && id !== undefined,
    queryFn: () => api.get<MaybeNoDb<Note>>(`/api/notes/${id}`),
  });
}

export function useCreateNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateNoteRequest) =>
      api.post<Note, CreateNoteRequest>("/api/notes", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notes"] });
    },
  });
}

export function useDeleteNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.delete(`/api/notes/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notes"] });
    },
  });
}
