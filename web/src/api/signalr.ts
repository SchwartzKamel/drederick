import { useCallback, useEffect, useRef, useState } from "react";
import {
  HubConnection,
  HubConnectionBuilder,
  HubConnectionState,
  LogLevel,
} from "@microsoft/signalr";
import type { ScanEventPayload, SignalRGroup } from "./types";
import { getBearerToken } from "./client";

export type ConnectionState = "connecting" | "connected" | "disconnected" | "error";

const EVENT_BUFFER_CAP = 500;
const CLIENT_METHOD = "scanEvent";
const HUB_PATH = "/hubs/events";

export function buildHubConnection(path = HUB_PATH): HubConnection {
  return new HubConnectionBuilder()
    .withUrl(path, {
      // SignalR passes the bearer through `?access_token=` for browser
      // WebSocket handshakes. `accessTokenFactory` is re-invoked on
      // reconnect, so token rotations via `setBearerToken` are picked up.
      accessTokenFactory: () => getBearerToken() ?? "",
    })
    .withAutomaticReconnect()
    .configureLogging(LogLevel.Warning)
    .build();
}

export type SignalREventsResult = {
  events: ScanEventPayload[];
  connected: boolean;
  state: ConnectionState;
  reconnect: () => void;
  clear: () => void;
};

/**
 * Subscribes to the SignalR events hub, joins the `group`, and returns a
 * capped sliding-window buffer of `ScanEventPayload`s. Cleans up on
 * unmount. The bearer token is re-read on each (re)connect.
 */
export function useSignalREvents(group: SignalRGroup): SignalREventsResult {
  const [events, setEvents] = useState<ScanEventPayload[]>([]);
  const [state, setState] = useState<ConnectionState>("disconnected");
  const connRef = useRef<HubConnection | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const conn = buildHubConnection();
    connRef.current = conn;
    let cancelled = false;

    conn.onreconnecting(() => setState("connecting"));
    conn.onreconnected(() => {
      setState("connected");
      conn.invoke("JoinScope", group).catch(() => {});
    });
    conn.onclose(() => setState("disconnected"));

    conn.on(CLIENT_METHOD, (payload: ScanEventPayload) => {
      setEvents((prev) => {
        const next = prev.length >= EVENT_BUFFER_CAP
          ? prev.slice(prev.length - EVENT_BUFFER_CAP + 1)
          : prev.slice();
        next.push(payload);
        return next;
      });
    });

    setState("connecting");
    conn
      .start()
      .then(() => {
        if (cancelled) return;
        setState("connected");
        return conn.invoke("JoinScope", group);
      })
      .catch(() => {
        if (!cancelled) setState("error");
      });

    return () => {
      cancelled = true;
      connRef.current = null;
      if (conn.state !== HubConnectionState.Disconnected) {
        conn.stop().catch(() => {});
      }
    };
  }, [group, tick]);

  const reconnect = useCallback(() => setTick((t) => t + 1), []);
  const clear = useCallback(() => setEvents([]), []);

  return {
    events,
    connected: state === "connected",
    state,
    reconnect,
    clear,
  };
}

/**
 * Returns the single most-recent event in `group`, or `null`. Intended
 * for dashboard tiles that want a one-line "last activity" summary
 * without keeping the full buffer around.
 */
export function useLatestEvent(group: SignalRGroup): ScanEventPayload | null {
  const { events } = useSignalREvents(group);
  return events.length === 0 ? null : (events[events.length - 1] ?? null);
}
