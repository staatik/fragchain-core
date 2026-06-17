import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

import {
  createAssessment,
  ExistingChainSummary,
  TriggerKind,
} from "../../api/assessments";
import { getCve } from "../../api/cves";
import { detailFromError } from "../../api/client";
import { Modal } from "../Modal";
import { ExistingChainOffer } from "./ExistingChainOffer";

interface CreateAssessmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** Textual CVE id ("CVE-YYYY-NNNN") to pre-fill, e.g. from the Explorer. */
  prefillCveId?: string;
}

/* Backend contract (fragchain/assessments/schemas.py + trigger_resolver.py):
 * - `cve_id` is the internal CVE row UUID and is REQUIRED — the modal
 *   resolves the textual id the analyst types via GET /cves/{cve_id}.
 * - `trigger.value` for kind=cve_id must be the textual "CVE-YYYY-NNNN"
 *   (regex-validated server-side), so for that kind the analyst enters the
 *   CVE exactly once and the trigger value is derived from it.
 * - ticket: free-form reference; psirt_url: must be https://.
 */
interface FormState {
  triggerKind: TriggerKind;
  /** Ticket reference / PSIRT URL — unused for kind=cve_id. */
  triggerValue: string;
  /** Textual CVE id; required for every kind (backend needs the UUID). */
  cve: string;
  contextNote: string;
}

interface OfferState {
  assessmentId: string;
  chain: ExistingChainSummary;
}

const TRIGGER_VALUE_LABEL: Record<Exclude<TriggerKind, "cve_id">, string> = {
  ticket: "Ticket Reference",
  psirt_url: "PSIRT URL",
};

const TRIGGER_VALUE_PLACEHOLDER: Record<Exclude<TriggerKind, "cve_id">, string> = {
  ticket: "e.g. SEC-4521",
  psirt_url: "e.g. https://vendor.example/psirt/advisory-001",
};

export function CreateAssessmentModal({
  isOpen,
  onClose,
  prefillCveId = "",
}: CreateAssessmentModalProps) {
  const navigate = useNavigate();

  const [form, setForm] = useState<FormState>({
    triggerKind: "cve_id",
    triggerValue: "",
    cve: prefillCveId,
    contextNote: "",
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [offer, setOffer] = useState<OfferState | null>(null);

  function handleChange<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    const cveText = form.cve.trim().toUpperCase();
    if (!cveText) {
      setError("CVE ID is required.");
      return;
    }
    const triggerValue =
      form.triggerKind === "cve_id" ? cveText : form.triggerValue.trim();
    if (!triggerValue) {
      setError(`${TRIGGER_VALUE_LABEL[form.triggerKind as Exclude<TriggerKind, "cve_id">]} is required.`);
      return;
    }

    setBusy(true);
    try {
      // Resolve the textual CVE id to the internal row UUID the backend
      // requires. GET /cves/{ident} accepts either form.
      let cveUuid: string;
      try {
        const row = await getCve(cveText);
        cveUuid = row.id;
      } catch (err) {
        if (axios.isAxiosError(err) && err.response?.status === 404) {
          setError(
            `${cveText} is not in the platform yet — add it first via Intel → Add CVE, then retry.`,
          );
          return;
        }
        throw err;
      }

      const resp = await createAssessment({
        cve_id: cveUuid,
        trigger: { kind: form.triggerKind, value: triggerValue },
        context_note: form.contextNote || null,
      });
      if (resp.existing_chain) {
        setOffer({ assessmentId: resp.assessment.id, chain: resp.existing_chain });
      } else {
        navigate(`/assessments/${resp.assessment.id}`);
      }
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setBusy(false);
    }
  }

  function handleOfferResolved(id: string) {
    onClose();
    navigate(`/assessments/${id}`);
  }

  const labelStyle: React.CSSProperties = {
    display: "flex",
    flexDirection: "column",
    gap: "var(--space-1)",
    fontSize: "var(--text-sm)",
    color: "var(--text-dim)",
  };

  const inputStyle: React.CSSProperties = {
    background: "var(--surface2)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-md)",
    color: "var(--text)",
    fontSize: "var(--text-base)",
    padding: "6px 10px",
    width: "100%",
    boxSizing: "border-box",
  };

  const formBody = (
    <form
      id="create-assessment-form"
      onSubmit={handleSubmit}
      style={{ display: "flex", flexDirection: "column", gap: "var(--space-4)" }}
    >
      <label style={labelStyle} htmlFor="ca-trigger-kind">
        Trigger Kind
        <select
          id="ca-trigger-kind"
          style={inputStyle}
          value={form.triggerKind}
          onChange={(e) => handleChange("triggerKind", e.target.value as TriggerKind)}
        >
          <option value="cve_id">CVE ID</option>
          <option value="ticket">Ticket</option>
          <option value="psirt_url">PSIRT URL</option>
        </select>
      </label>

      {form.triggerKind !== "cve_id" && (
        <label style={labelStyle} htmlFor="ca-trigger-value">
          {TRIGGER_VALUE_LABEL[form.triggerKind]}
          <input
            id="ca-trigger-value"
            type="text"
            style={inputStyle}
            value={form.triggerValue}
            onChange={(e) => handleChange("triggerValue", e.target.value)}
            placeholder={TRIGGER_VALUE_PLACEHOLDER[form.triggerKind]}
            required
          />
        </label>
      )}

      <label style={labelStyle} htmlFor="ca-cve-id">
        CVE ID
        <input
          id="ca-cve-id"
          type="text"
          style={inputStyle}
          value={form.cve}
          onChange={(e) => handleChange("cve", e.target.value)}
          placeholder="CVE-2026-1234"
          required
        />
        {form.triggerKind !== "cve_id" && (
          <span style={{ fontSize: "var(--text-xs)" }}>
            The CVE this {form.triggerKind === "ticket" ? "ticket" : "advisory"} resolves to
            (v1 does not auto-resolve triggers).
          </span>
        )}
      </label>

      <label style={labelStyle} htmlFor="ca-context-note">
        Context Note
        <textarea
          id="ca-context-note"
          style={{ ...inputStyle, resize: "vertical", minHeight: 72 }}
          value={form.contextNote}
          onChange={(e) => handleChange("contextNote", e.target.value)}
          maxLength={2000}
          placeholder="Optional context for this assessment…"
        />
      </label>

      {error && (
        <div
          role="alert"
          style={{
            color: "var(--danger)",
            fontSize: "var(--text-sm)",
            padding: "8px 10px",
            background: "rgba(248,113,113,0.08)",
            borderRadius: "var(--radius-md)",
          }}
        >
          {error}
        </div>
      )}
    </form>
  );

  const offerBody = offer ? (
    <ExistingChainOffer
      assessmentId={offer.assessmentId}
      chain={offer.chain}
      onResolved={handleOfferResolved}
    />
  ) : null;

  return (
    <Modal
      open={isOpen}
      onClose={busy ? () => undefined : onClose}
      title={offer ? "Existing Chain Found" : "New Assessment"}
      dismissOnBackdrop={!busy}
      footer={
        offer ? undefined : (
          <>
            <button
              type="button"
              className="btn ghost"
              onClick={onClose}
              disabled={busy}
            >
              Cancel
            </button>
            <button
              type="submit"
              form="create-assessment-form"
              className="btn active"
              disabled={busy}
            >
              {busy ? "Creating…" : "Create"}
            </button>
          </>
        )
      }
    >
      {offer ? offerBody : formBody}
    </Modal>
  );
}
