import { useCallback, useEffect, useState } from "react";
import {
  type ArtifactPlan,
  type Assessment,
  type AssessmentSource,
  type DetectabilityAssessment,
  type GeneratedArtifact,
  type GeneratedArtifactType,
  type LoopRun,
  type SourceCreateRequest,
  addSource as apiAddSource,
  approveArtifact as apiApproveArtifact,
  closeAssessment as apiCloseAssessment,
  deleteSource as apiDeleteSource,
  generateArtifact as apiGenerateArtifact,
  rejectArtifact as apiRejectArtifact,
  validateArtifact as apiValidateArtifact,
  getArtifactPlan,
  getAssessment,
  getDetectability,
  listArtifacts,
  listLoopRuns,
  listSources,
  runLoop as apiRunLoop,
  useExistingChain as apiUseExistingChain,
} from "../api/assessments";
import { useWebSocket } from "./useWebSocket";
import type { WebSocketMessage } from "./useWebSocket";
import { detailFromError } from "../api/client";

type LoopRunsByLoop = { 1: LoopRun[]; 2: LoopRun[]; 3: LoopRun[] };

interface AssessmentEventPayload {
  assessment_id?: string;
  source_id?: string;
  loop_number?: 1 | 2 | 3;
  version?: number;
  status?: string;
}

export interface UseAssessmentResult {
  assessment: Assessment | null;
  sources: AssessmentSource[];
  runs: LoopRunsByLoop;
  detectability: DetectabilityAssessment | null;
  artifactPlan: ArtifactPlan | null;
  artifacts: GeneratedArtifact[];
  state: "loading" | "ready" | "error";
  error: string | null;
  refetchAssessment: () => Promise<void>;
  refetchSources: () => Promise<void>;
  refetchRuns: (loop?: 1 | 2 | 3) => Promise<void>;
  refetchAll: () => Promise<void>;
  addSource: (req: SourceCreateRequest) => Promise<AssessmentSource>;
  deleteSource: (sourceId: string, rationale: string) => Promise<void>;
  runLoop: (loop: 1 | 2 | 3, opts?: { overrideRationale?: string }) => Promise<LoopRun>;
  useExistingChain: (chainId: string) => Promise<LoopRun>;
  closeAssessment: (note?: string) => Promise<void>;
  generateArtifact: (type: GeneratedArtifactType) => Promise<GeneratedArtifact>;
  runArtifactValidation: (
    artifactId: string,
    action: "validate" | "approve" | "reject",
    reason?: string,
  ) => Promise<void>;
  wsState: ReturnType<typeof useWebSocket>["state"];
}

export function useAssessment(id: string): UseAssessmentResult {
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [sources, setSources] = useState<AssessmentSource[]>([]);
  const [runs, setRuns] = useState<LoopRunsByLoop>({ 1: [], 2: [], 3: [] });
  const [detectability, setDetectability] = useState<DetectabilityAssessment | null>(null);
  const [artifactPlan, setArtifactPlan] = useState<ArtifactPlan | null>(null);
  const [artifacts, setArtifacts] = useState<GeneratedArtifact[]>([]);
  const [state, setStateValue] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);

  const refetchAssessment = useCallback(async () => {
    setAssessment(await getAssessment(id));
  }, [id]);

  const refetchSources = useCallback(async () => {
    setSources(await listSources(id));
  }, [id]);

  const refetchRuns = useCallback(async (loop?: 1 | 2 | 3) => {
    if (loop) {
      const fresh = await listLoopRuns(id, loop);
      setRuns((prev) => ({ ...prev, [loop]: fresh }));
      return;
    }
    const [r1, r2, r3] = await Promise.all([
      listLoopRuns(id, 1),
      listLoopRuns(id, 2),
      listLoopRuns(id, 3),
    ]);
    setRuns({ 1: r1, 2: r2, 3: r3 });
  }, [id]);

  // Detectability is advisory: a fetch failure must never break the
  // workspace, so errors collapse to null instead of propagating.
  const refetchDetectability = useCallback(async () => {
    try {
      setDetectability(await getDetectability(id));
    } catch {
      setDetectability(null);
    }
  }, [id]);

  // The artifact plan is advisory too (compatibility mode): a fetch failure
  // must never break the workspace, so errors collapse to null as well.
  const refetchArtifactPlan = useCallback(async () => {
    try {
      setArtifactPlan(await getArtifactPlan(id));
    } catch {
      setArtifactPlan(null);
    }
  }, [id]);

  // Generated artifacts are advisory output too: a fetch failure must never
  // break the workspace, so errors collapse to an empty list.
  const refetchArtifacts = useCallback(async () => {
    try {
      setArtifacts(await listArtifacts(id));
    } catch {
      setArtifacts([]);
    }
  }, [id]);

  const refetchAll = useCallback(async () => {
    setStateValue("loading");
    setError(null);
    try {
      await Promise.all([
        refetchAssessment(),
        refetchSources(),
        refetchRuns(),
        refetchDetectability(),
        refetchArtifactPlan(),
        refetchArtifacts(),
      ]);
      setStateValue("ready");
    } catch (e) {
      setError(detailFromError(e));
      setStateValue("error");
    }
  }, [refetchAssessment, refetchSources, refetchRuns, refetchDetectability, refetchArtifactPlan, refetchArtifacts]);

  useEffect(() => {
    void refetchAll();
  }, [refetchAll]);

  // WebSocket subscription — react to live backend events for this assessment.
  const { state: wsState, last } = useWebSocket<AssessmentEventPayload>({
    filter: (msg: WebSocketMessage) =>
      typeof msg.type === "string" &&
      msg.type.startsWith("assessment.") &&
      (msg.payload as AssessmentEventPayload | undefined)?.assessment_id === id,
  });

  useEffect(() => {
    if (!last) return;
    const t = last.type;
    if (t === "assessment.loop.run.started" || t === "assessment.loop.run.completed") {
      const loop = (last.payload as AssessmentEventPayload).loop_number;
      void refetchRuns(loop);
      if (t === "assessment.loop.run.completed") {
        void refetchAssessment();
        void refetchDetectability();
        void refetchArtifactPlan();
      }
    } else if (t === "assessment.source.embedded") {
      void refetchSources();
    } else if (t === "assessment.artifact.generated") {
      void refetchArtifacts();
    }
  }, [last, refetchRuns, refetchAssessment, refetchSources, refetchDetectability, refetchArtifactPlan, refetchArtifacts]);

  // Poll while anything is in flight. The WS event bus is in-process per
  // container — events emitted by the Celery worker never reach the API
  // process's WS subscribers in the deployed topology — so an open socket
  // is NOT evidence that completion events will arrive. Poll whenever a
  // loop run is 'running' or an artifact is 'generating'; when idle, only
  // the WS-down case matters and there is nothing to poll for anyway.
  useEffect(() => {
    const anyInFlight =
      runs[1].some((r) => r.status === "running") ||
      runs[2].some((r) => r.status === "running") ||
      runs[3].some((r) => r.status === "running") ||
      artifacts.some((a) => a.status === "generating");
    if (!anyInFlight) return;
    const id = setInterval(() => {
      void refetchRuns();
      void refetchArtifacts();
      // A finished run also updates assessment state + advisory cards.
      void refetchAssessment();
      void refetchDetectability();
      void refetchArtifactPlan();
    }, 3000);
    return () => clearInterval(id);
  }, [runs, artifacts, refetchRuns, refetchArtifacts, refetchAssessment, refetchDetectability, refetchArtifactPlan]);

  const addSource = useCallback(async (req: SourceCreateRequest) => {
    const result = await apiAddSource(id, req);
    await refetchSources();
    return result;
  }, [id, refetchSources]);

  const deleteSource = useCallback(async (sourceId: string, rationale: string) => {
    await apiDeleteSource(id, sourceId, rationale);
    await refetchSources();
  }, [id, refetchSources]);

  const runLoop = useCallback(
    async (loop: 1 | 2 | 3, opts: { overrideRationale?: string } = {}) => {
      // Async: the endpoint dispatches to the worker and returns a 'running'
      // row. The WS 'assessment.loop.run.completed' handler + the polling
      // fallback refetch runs/assessment/detectability/plan when it finishes.
      setDetectability(null);
      setArtifactPlan(null);
      const run = await apiRunLoop(id, loop, opts);
      await refetchRuns(loop);   // surface the 'running' row immediately
      return run;
    },
    [id, refetchRuns],
  );

  const useExistingChain = useCallback(async (chainId: string) => {
    const run = await apiUseExistingChain(id, chainId);
    await Promise.all([refetchRuns(1), refetchAssessment()]);
    return run;
  }, [id, refetchRuns, refetchAssessment]);

  const generateArtifact = useCallback(
    async (type: GeneratedArtifactType) => {
      // Async: the endpoint dispatches to the worker and returns a
      // 'generating' row. The WS 'assessment.artifact.generated' handler +
      // the polling fallback refetch when it finishes.
      const row = await apiGenerateArtifact(id, type);
      await refetchArtifacts(); // surface the 'generating' row immediately
      return row;
    },
    [id, refetchArtifacts],
  );

  const runArtifactValidation = useCallback(
    async (
      artifactId: string,
      action: "validate" | "approve" | "reject",
      reason?: string,
    ) => {
      if (action === "validate") await apiValidateArtifact(id, artifactId);
      else if (action === "approve") await apiApproveArtifact(id, artifactId);
      else {
        // The reject endpoint requires a non-empty reason (min_length=1) —
        // enforce it here rather than letting an empty reason 422 server-side.
        if (!reason || !reason.trim()) {
          throw new Error("A reason is required to reject an artifact");
        }
        await apiRejectArtifact(id, artifactId, reason);
      }
      await refetchArtifacts();
    },
    [id, refetchArtifacts],
  );

  const closeAssessment = useCallback(async (note?: string) => {
    await apiCloseAssessment(id, note ? { note } : {});
    await refetchAssessment();
  }, [id, refetchAssessment]);

  return {
    assessment, sources, runs, detectability, artifactPlan, artifacts, state, error,
    refetchAssessment, refetchSources, refetchRuns, refetchAll,
    addSource, deleteSource, runLoop, useExistingChain, closeAssessment, generateArtifact,
    runArtifactValidation,
    wsState,
  };
}
