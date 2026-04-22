import { useEffect, useState } from "react";
import {
  HubConnection,
  HubConnectionBuilder,
  HubConnectionState,
  LogLevel,
} from "@microsoft/signalr";
import { useQueryClient } from "@tanstack/react-query";

export type ConnectionState = "connecting" | "connected" | "disconnected" | "error";

export interface DrederickEvent {
  type: string;
  payload: unknown;
  receivedAt: number;
}

export function createHubConnection(path = "/hubs/events"): HubConnection {
  return new HubConnectionBuilder()
    .withUrl(path)
    .withAutomaticReconnect()
    .configureLogging(LogLevel.Warning)
    .build();
}

/**
 * Connects to the events hub on mount, tracks state, and appends incoming
 * events into TanStack Query cache under the `["hub-events"]` key.
 * Phase 2 will extend this with typed event payloads.
 */
export function useSignalREvents(path = "/hubs/events") {
  const qc = useQueryClient();
  const [state, setState] = useState<ConnectionState>("disconnected");

  useEffect(() => {
    const conn = createHubConnection(path);
    let cancelled = false;

    conn.onreconnecting(() => setState("connecting"));
    conn.onreconnected(() => setState("connected"));
    conn.onclose(() => setState("disconnected"));

    conn.on("event", (raw: { type: string; payload: unknown }) => {
      const event: DrederickEvent = { ...raw, receivedAt: Date.now() };
      qc.setQueryData<DrederickEvent[]>(["hub-events"], (prev) => {
        const next = prev ? [...prev, event] : [event];
        return next.slice(-500);
      });
    });

    setState("connecting");
    conn
      .start()
      .then(() => {
        if (!cancelled) setState("connected");
      })
      .catch(() => {
        if (!cancelled) setState("error");
      });

    return () => {
      cancelled = true;
      if (conn.state !== HubConnectionState.Disconnected) {
        conn.stop().catch(() => {});
      }
    };
  }, [path, qc]);

  return { state };
}
