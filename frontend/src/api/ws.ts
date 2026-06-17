/* F-003 — WebSocket ticket client.
 *
 * Browsers can't attach an Authorization header to a WS handshake, so
 * the backend issues short-lived single-use tickets. We exchange the
 * long-lived JWT (sent in the Authorization header on the HTTPS POST)
 * for a one-shot ticket and only that ticket appears in the WS URL.
 *
 * The ticket TTL is short (~60s) and the value is consumed on the
 * first successful WS connect, so a leaked ticket from access logs or
 * referrer headers can be replayed only inside that window — and only
 * once. The full JWT never traverses a query string.
 */
import { api } from "./client";

export interface WsTicket {
  ticket: string;
  expires_in: number;
}

/** Request a fresh single-use WebSocket ticket. */
export async function fetchWsTicket(): Promise<WsTicket> {
  const r = await api.post<WsTicket>("/ws/ticket");
  return r.data;
}
