import { useState } from "react";
import { Link } from "react-router-dom";
import dayjs from "dayjs";

import { AppShell, EmptyState, Spinner } from "../components";
import { type AssessmentState } from "../api/assessments";
import { useAssessments, type UseAssessmentsFilters } from "../hooks/useAssessments";
import { CreateAssessmentModal } from "../components/assessments/CreateAssessmentModal";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ageLabel(s: string | null | undefined): string {
  if (!s) return "—";
  const d = dayjs(s);
  if (!d.isValid()) return "—";
  const ms = Date.now() - d.valueOf();
  const mins = Math.floor(ms / 60_000);
  if (mins < 1) return "<1m";
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  return `${days}d`;
}

// ---------------------------------------------------------------------------
// State filter options
// ---------------------------------------------------------------------------

interface StateOption {
  value: string;
  label: string;
}

const STATE_OPTIONS: StateOption[] = [
  { value: "all", label: "All" },
  { value: "created", label: "Created" },
  { value: "loop1_done", label: "Loop 1 done" },
  { value: "loop2_done", label: "Loop 2 done" },
  { value: "loop3_done", label: "Loop 3 done" },
  { value: "completed", label: "Completed" },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AssessmentsList() {
  const [stateFilter, setStateFilter] = useState<string>("all");
  const [modalOpen, setModalOpen] = useState(false);

  const filters: UseAssessmentsFilters = {};
  if (stateFilter !== "all") {
    filters.state = stateFilter as AssessmentState;
  }

  const { data, state, error } = useAssessments(filters);

  const contextActions = (
    <button className="btn" onClick={() => setModalOpen(true)}>
      + New Assessment
    </button>
  );

  return (
    <AppShell title="Coverage Assessments" contextActions={contextActions}>
      {/* Filter bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "var(--space-3)",
          marginBottom: "var(--space-4)",
        }}
      >
        <label
          htmlFor="assessments-state-filter"
          style={{ color: "var(--text-dim)", fontSize: "var(--text-sm)" }}
        >
          State
        </label>
        <select
          id="assessments-state-filter"
          className="input"
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value)}
          style={{ width: "160px" }}
          aria-label="State"
        >
          {STATE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>

      {/* Content */}
      {state === "loading" ? (
        <div style={{ padding: "var(--space-8)", textAlign: "center" }}>
          <Spinner large />
        </div>
      ) : state === "error" ? (
        <div style={{ padding: "var(--space-6)" }}>
          <EmptyState title="Failed to load assessments" hint={error ?? undefined} />
        </div>
      ) : data.length === 0 ? (
        <div style={{ padding: "var(--space-6)" }}>
          <EmptyState
            title="Start your first coverage assessment"
            hint="Create an assessment to map a CVE against your detection coverage."
            action={
              // Same mechanism as the header button — a /assessments/new link
              // would fall into the :id route and render "not found".
              <button className="btn" onClick={() => setModalOpen(true)}>
                New Assessment
              </button>
            }
          />
        </div>
      ) : (
        <table className="data-table" style={{ width: "100%" }}>
          <thead>
            <tr>
              <th>CVE / Trigger</th>
              <th>State</th>
              <th>Created</th>
              <th>Last activity</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row) => (
              <tr key={row.id}>
                <td>
                  <Link
                    to={`/assessments/${row.id}`}
                    className="mono"
                    style={{ color: "var(--accent)" }}
                  >
                    {row.initial_trigger.value}
                  </Link>
                </td>
                <td>
                  <span className="mono text-sm">{row.state}</span>
                </td>
                <td style={{ color: "var(--text-dim)", fontSize: "var(--text-sm)" }}>
                  {ageLabel(row.created_at)}
                </td>
                <td style={{ color: "var(--text-dim)", fontSize: "var(--text-sm)" }}>
                  {ageLabel(row.updated_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {modalOpen && (
        <CreateAssessmentModal isOpen onClose={() => setModalOpen(false)} />
      )}
    </AppShell>
  );
}
