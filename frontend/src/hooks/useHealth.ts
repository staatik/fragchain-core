import { useEffect, useRef, useState } from "react";
import { fetchHealth, HealthResponse } from "../api/health";

const POLL_MS = 30_000;

export type IndicatorState = "ok" | "warn" | "error" | "off";

export interface UseHealthResult {
  data: HealthResponse | null;
  loading: boolean;
  indicators: Record<string, IndicatorState>;
}

function toIndicator(serviceStatus: string | undefined): IndicatorState {
  if (serviceStatus === "ok") return "ok";
  if (serviceStatus === "error") return "error";
  if (serviceStatus === undefined) return "off";
  return "warn";
}

export function useHealth(): UseHealthResult {
  const [data, setData] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await fetchHealth();
        if (!cancelled) setData(r);
      } catch {
        if (!cancelled) {
          setData({
            status: "error",
            services: {
              postgres: { status: "error" },
              redis: { status: "error" },
              minio: { status: "error" },
              qdrant: { status: "error" },
              litellm: { status: "error" },
            },
          });
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    tick();
    timer.current = window.setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      if (timer.current !== null) window.clearInterval(timer.current);
    };
  }, []);

  // LiteLLM + Qdrant are checked by /api/v1/health (real health).
  // OpenCTI + Sigma stubs default to "ok" until M4/M12 wire in real health.
  const indicators: Record<string, IndicatorState> = {
    litellm: toIndicator(data?.services?.litellm?.status),
    qdrant: toIndicator(data?.services?.qdrant?.status),
    opencti: "ok",
    sigma: "ok",
  };

  return { data, loading, indicators };
}
