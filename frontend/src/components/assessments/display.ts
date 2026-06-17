/** Shared display maps for assessment-analysis surfaces.
 *
 * Single source of truth so the workspace cards and the CVE Explorer
 * badges cannot drift (badging spec, 2026-06-10).
 */

import type { BadgeVariant } from "../Badge";

export const CLASS_COLOR: Record<string, string> = {
  directly_detectable: "var(--accent3)",
  indirectly_detectable: "var(--accent)",
  environment_dependent: "var(--warning)",
  control_only: "var(--accent2)",
  insufficient_information: "var(--danger)",
};

export const CLASS_VARIANT: Record<string, BadgeVariant> = {
  directly_detectable: "success",
  indirectly_detectable: "accent",
  environment_dependent: "warning",
  control_only: "accent2",
  insufficient_information: "danger",
};

export const CLASS_LABEL: Record<string, string> = {
  directly_detectable: "Directly detectable",
  indirectly_detectable: "Indirectly detectable",
  environment_dependent: "Environment-dependent",
  control_only: "Control-only",
  insufficient_information: "Insufficient information",
};

/** Compact variants for table cells. */
export const CLASS_SHORT: Record<string, string> = {
  directly_detectable: "direct",
  indirectly_detectable: "indirect",
  environment_dependent: "env-dependent",
  control_only: "control-only",
  insufficient_information: "insufficient",
};

export const TYPE_LABEL: Record<string, string> = {
  mitigation_plan: "Mitigation plan",
  analyst_research_task: "Analyst research task",
  telemetry_contract: "Telemetry contract",
};
