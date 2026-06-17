import { useCallback, useEffect, useState } from "react";
import {
  type Assessment,
  type AssessmentState,
  listAssessments,
} from "../api/assessments";
import { detailFromError } from "../api/client";

export interface UseAssessmentsFilters {
  state?: AssessmentState;
  creator_id?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface UseAssessmentsResult {
  data: Assessment[];
  state: "loading" | "ready" | "error";
  error: string | null;
  refetch: () => Promise<void>;
}

export function useAssessments(filters: UseAssessmentsFilters): UseAssessmentsResult {
  const [data, setData] = useState<Assessment[]>([]);
  const [state, setStateValue] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);

  const refetch = useCallback(async () => {
    setStateValue("loading");
    setError(null);
    try {
      const apiFilters: Parameters<typeof listAssessments>[0] = {};
      if (filters.state) apiFilters.state = filters.state;
      if (filters.creator_id) apiFilters.creator_id = filters.creator_id;
      if (filters.limit !== undefined) apiFilters.limit = filters.limit;
      if (filters.offset !== undefined) apiFilters.offset = filters.offset;
      let rows = await listAssessments(apiFilters);
      if (filters.search) {
        const needle = filters.search.toLowerCase();
        rows = rows.filter((r) =>
          r.initial_trigger.value.toLowerCase().includes(needle),
        );
      }
      setData(rows);
      setStateValue("ready");
    } catch (e) {
      setError(detailFromError(e));
      setStateValue("error");
    }
  }, [
    filters.state, filters.creator_id, filters.search,
    filters.limit, filters.offset,
  ]);

  useEffect(() => {
    void refetch();
  }, [refetch]);

  return { data, state, error, refetch };
}
