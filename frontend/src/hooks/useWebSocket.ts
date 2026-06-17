import { useEffect, useRef, useState } from "react";

import { fetchWsTicket } from "../api/ws";

export type WebSocketState = "connecting" | "open" | "closed" | "error";

export interface WebSocketMessage<T = unknown> {
  /** Event type discriminator from the backend's WebSocket bus. */
  type: string;
  /** Payload — shape is event-type specific. */
  payload?: T;
  [key: string]: unknown;
}

export interface UseWebSocketOptions {
  /** Absolute or root-relative URL; defaults to `/ws/events`. */
  url?: string;
  /** Disable the connection entirely. */
  enabled?: boolean;
  /** Filter messages by `type`. When omitted, every message is delivered. */
  filter?: (msg: WebSocketMessage) => boolean;
  /** Initial reconnect delay in ms. Doubles each retry up to `maxBackoff`. */
  backoff?: number;
  /** Cap for exponential backoff. */
  maxBackoff?: number;
}

export interface UseWebSocketResult<T = unknown> {
  state: WebSocketState;
  last: WebSocketMessage<T> | null;
  /** Manual reconnect (resets the backoff counter). */
  reconnect: () => void;
  /** Send a JSON-encoded message back over the socket. */
  send: (msg: unknown) => boolean;
}

/** Resolve the WebSocket URL.
 *
 *  Accepts:
 *   - absolute `wss://host/path`
 *   - protocol-relative `//host/path`
 *   - root-relative `/ws/events`
 *
 *  F-003: the URL carries a single-use ticket (~60s TTL, one-shot)
 *  rather than the long-lived JWT.
 */
function resolveUrl(input: string | undefined, ticket: string | null): string {
  const base = input ?? "/ws/events";
  let url: string;
  if (/^wss?:\/\//i.test(base)) {
    url = base;
  } else if (typeof window !== "undefined") {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const path = base.startsWith("/") ? base : `/${base}`;
    url = `${proto}//${host}${path}`;
  } else {
    url = base;
  }
  if (ticket) {
    const sep = url.includes("?") ? "&" : "?";
    url = `${url}${sep}ticket=${encodeURIComponent(ticket)}`;
  }
  return url;
}

/** Auto-reconnecting WebSocket subscription.
 *
 *  Reconnect strategy:
 *   - exponential backoff starting at `backoff` (default 1s)
 *   - caps at `maxBackoff` (default 30s)
 *   - resets on a successful `open`
 *   - drops the socket entirely on unmount; no zombie connections
 *
 *  Authentication (F-003): the hook calls `POST /ws/ticket` over
 *  authenticated HTTPS for every open attempt, then connects with the
 *  one-shot ticket. The full JWT never appears in the WS URL. If the
 *  ticket fetch fails we still attempt the connect — the backend
 *  closes the socket with policy-violation (1008) so the user-visible
 *  state is identical and the retry loop kicks in.
 */
export function useWebSocket<T = unknown>(opts: UseWebSocketOptions = {}): UseWebSocketResult<T> {
  const { enabled = true, filter, backoff = 1000, maxBackoff = 30_000, url } = opts;
  const [state, setState] = useState<WebSocketState>("closed");
  const [last, setLast] = useState<WebSocketMessage<T> | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<number>(0);
  const timerRef = useRef<number | null>(null);
  const cancelledRef = useRef<boolean>(false);

  const filterRef = useRef(filter);
  filterRef.current = filter;

  const clearTimer = () => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  };

  const open = async () => {
    if (!enabled || cancelledRef.current) return;
    setState("connecting");
    let ticket: string | null = null;
    try {
      const resp = await fetchWsTicket();
      ticket = resp.ticket;
    } catch {
      // Fall through with no ticket — the backend will reject and the
      // reconnect loop will retry. We don't surface ticket-fetch errors
      // as a distinct state because the UI only cares about open/closed.
      ticket = null;
    }
    if (cancelledRef.current) return;
    const target = resolveUrl(url, ticket);
    let ws: WebSocket;
    try {
      ws = new WebSocket(target);
    } catch {
      setState("error");
      schedule();
      return;
    }
    wsRef.current = ws;

    ws.onopen = () => {
      retryRef.current = 0;
      setState("open");
    };
    ws.onmessage = (ev) => {
      let parsed: WebSocketMessage<T> | null = null;
      try {
        parsed = typeof ev.data === "string" ? (JSON.parse(ev.data) as WebSocketMessage<T>) : null;
      } catch {
        parsed = { type: "raw", payload: ev.data as unknown as T };
      }
      if (!parsed) return;
      if (filterRef.current && !filterRef.current(parsed)) return;
      setLast(parsed);
    };
    ws.onerror = () => setState("error");
    ws.onclose = () => {
      setState("closed");
      wsRef.current = null;
      if (!cancelledRef.current && enabled) schedule();
    };
  };

  const schedule = () => {
    clearTimer();
    const attempt = retryRef.current + 1;
    retryRef.current = attempt;
    const delay = Math.min(maxBackoff, backoff * 2 ** (attempt - 1));
    timerRef.current = window.setTimeout(() => {
      void open();
    }, delay);
  };

  useEffect(() => {
    cancelledRef.current = false;
    if (enabled) void open();
    return () => {
      cancelledRef.current = true;
      clearTimer();
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
        wsRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, url]);

  const reconnect = () => {
    clearTimer();
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
      wsRef.current = null;
    }
    retryRef.current = 0;
    void open();
  };

  const send = (msg: unknown): boolean => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    try {
      ws.send(typeof msg === "string" ? msg : JSON.stringify(msg));
      return true;
    } catch {
      return false;
    }
  };

  return { state, last, reconnect, send };
}
