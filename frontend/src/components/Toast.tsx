import { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

export type ToastVariant = "info" | "success" | "warning" | "error";

export interface ToastInput {
  title?: string;
  message: ReactNode;
  variant?: ToastVariant;
  /** Auto-dismiss after N ms. Pass 0 to keep until user dismisses. Default 4000. */
  durationMs?: number;
}

interface ToastRecord extends ToastInput {
  id: string;
  variant: ToastVariant;
  durationMs: number;
}

interface ToastContextValue {
  toast: (input: ToastInput) => string;
  dismiss: (id: string) => void;
  success: (message: ReactNode, title?: string) => string;
  error: (message: ReactNode, title?: string) => string;
  warning: (message: ReactNode, title?: string) => string;
  info: (message: ReactNode, title?: string) => string;
}

const Ctx = createContext<ToastContextValue | null>(null);

let toastSeq = 0;
function newId(): string {
  toastSeq += 1;
  return `t${Date.now().toString(36)}-${toastSeq}`;
}

/** Hosts the toast stack and exposes the toast API via context.
 *
 *  Default duration is 4s. Error toasts default to 6s so the user has
 *  time to read them. Pass `durationMs: 0` to keep a toast pinned.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastRecord[]>([]);
  const timers = useRef<Map<string, number>>(new Map());

  const dismiss = useCallback((id: string) => {
    setToasts((cur) => cur.filter((t) => t.id !== id));
    const handle = timers.current.get(id);
    if (handle !== undefined) {
      window.clearTimeout(handle);
      timers.current.delete(id);
    }
  }, []);

  const toast = useCallback((input: ToastInput): string => {
    const variant: ToastVariant = input.variant ?? "info";
    const durationMs = input.durationMs ?? (variant === "error" ? 6000 : 4000);
    const record: ToastRecord = { ...input, id: newId(), variant, durationMs };
    setToasts((cur) => [...cur, record]);
    if (durationMs > 0) {
      const handle = window.setTimeout(() => dismiss(record.id), durationMs);
      timers.current.set(record.id, handle);
    }
    return record.id;
  }, [dismiss]);

  useEffect(() => {
    const map = timers.current;
    return () => {
      map.forEach((h) => window.clearTimeout(h));
      map.clear();
    };
  }, []);

  const value = useMemo<ToastContextValue>(() => ({
    toast,
    dismiss,
    success: (m, t) => toast({ message: m, title: t, variant: "success" }),
    error:   (m, t) => toast({ message: m, title: t, variant: "error" }),
    warning: (m, t) => toast({ message: m, title: t, variant: "warning" }),
    info:    (m, t) => toast({ message: m, title: t, variant: "info" }),
  }), [toast, dismiss]);

  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="toast-stack" aria-live="polite" aria-atomic="false">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.variant}`} role="status">
            <span className="toast-bar" />
            <div className="toast-body">
              {t.title && <div className="toast-title">{t.title}</div>}
              <div className="toast-message">{t.message}</div>
            </div>
            <button
              type="button"
              className="toast-dismiss"
              aria-label="Dismiss notification"
              onClick={() => dismiss(t.id)}
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(Ctx);
  if (!ctx) {
    throw new Error("useToast must be used inside <ToastProvider>");
  }
  return ctx;
}
