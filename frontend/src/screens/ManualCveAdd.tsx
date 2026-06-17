import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  Badge,
  Dropdown,
  Spinner,
  useToast,
} from "../components";
import { api, detailFromError } from "../api/client";

interface ManualCveResponse {
  id: string;
  cve_id: string;
  status: string;
  documents_inserted: number;
  synthesis_queued: boolean;
}

type TlpLevel = "tlp:clear" | "tlp:green" | "tlp:amber" | "tlp:amber+strict" | "tlp:red";

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,7}$/;
const DESCRIPTION_MIN = 40;
const DESCRIPTION_MAX = 64_000;
const REF_MAX = 12;

/** Manual CVE add — paste an advisory and run the full pipeline.
 *
 *  Bypasses the connector ingest path. Use when:
 *   - the CVE isn't in OpenCTI / NVD yet (zero-day, internal advisory)
 *   - a connector is offline and you have the text in hand
 *   - you want to evaluate the platform with a hand-crafted fixture
 *
 *  Submits to POST /api/v1/cves/manual which inserts a cves row +
 *  source documents, flips the row to ``synthesizing``, and dispatches
 *  the synth Celery task. On success the screen redirects to
 *  /chains/<cve_id> so the analyst can watch the chain materialise.
 */
export function ManualCveAdd() {
  const navigate = useNavigate();
  const toast = useToast();

  const [cveId, setCveId] = useState("");
  const [description, setDescription] = useState("");
  const [references, setReferences] = useState<string[]>([""]);
  const [cvssScore, setCvssScore] = useState<string>("");
  const [cvssVector, setCvssVector] = useState<string>("");
  const [cisaKev, setCisaKev] = useState(false);
  const [productsText, setProductsText] = useState<string>("");
  const [tlp, setTlp] = useState<TlpLevel>("tlp:clear");

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateRef = (idx: number, value: string) => {
    setReferences((cur) => cur.map((u, i) => (i === idx ? value : u)));
  };
  const addRefField = () => {
    if (references.length >= REF_MAX) return;
    setReferences((cur) => [...cur, ""]);
  };
  const removeRefField = (idx: number) => {
    setReferences((cur) => (cur.length === 1 ? [""] : cur.filter((_, i) => i !== idx)));
  };

  const cveIdNormalized = cveId.trim().toUpperCase();
  const cveIdValid = CVE_ID_PATTERN.test(cveIdNormalized);
  const descriptionLen = description.length;
  const descriptionValid =
    descriptionLen >= DESCRIPTION_MIN && descriptionLen <= DESCRIPTION_MAX;
  const cvssParsed = cvssScore.trim() === "" ? null : Number(cvssScore);
  const cvssValid =
    cvssParsed === null || (Number.isFinite(cvssParsed) && cvssParsed >= 0 && cvssParsed <= 10);

  const canSubmit = cveIdValid && descriptionValid && cvssValid && !submitting;

  const parseProducts = (raw: string): { vendor: string; product: string }[] => {
    return raw
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((entry) => {
        if (entry.includes(":")) {
          const [vendor, product] = entry.split(":");
          return { vendor: vendor.trim(), product: product.trim() };
        }
        return { vendor: entry, product: "" };
      })
      .filter((e) => e.vendor);
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);

    const refs = references.map((r) => r.trim()).filter(Boolean);
    const products = parseProducts(productsText);

    const body: Record<string, unknown> = {
      cve_id: cveIdNormalized,
      description,
      references: refs,
      cisa_kev: cisaKev,
      tlp,
      affected_products: products,
    };
    if (cvssParsed !== null) body.cvss_score = cvssParsed;
    if (cvssVector.trim()) body.cvss_vector = cvssVector.trim();

    try {
      const r = await api.post<ManualCveResponse>("/cves/manual", body);
      toast.success(
        `${r.data.cve_id} is now synthesizing (${r.data.documents_inserted} source documents). Redirecting to chain viewer.`,
        "CVE submitted",
      );
      // Small delay so the worker has a chance to register the task before
      // the chain viewer asks for the (still-empty) chain.
      setTimeout(() => navigate(`/chains/${r.data.cve_id}`), 600);
    } catch (err) {
      setError(detailFromError(err, "Submission failed"));
      setSubmitting(false);
    }
  };

  return (
    <div className="manual-cve-wrap">
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Manually add a CVE</div>
            <div className="text-sm text-dim">
              Paste an advisory (text or markdown) and run the full pipeline:
              synthesize → coverage → rules → review queue. Bypasses connector
              ingest — useful for zero-days, internal advisories, or offline
              connector evaluation.
            </div>
          </div>
        </div>

        <form className="manual-cve-form" onSubmit={onSubmit}>
          <div className="manual-cve-grid">
            <div className="form-group">
              <label className="form-label" htmlFor="manual-cve-id">CVE ID</label>
              <input
                id="manual-cve-id"
                className={`input mono${cveId && !cveIdValid ? " invalid" : ""}`}
                placeholder="CVE-2026-50001"
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              <div className="form-hint">
                Pattern <code className="mono">CVE-YYYY-NNNN+</code>. Will reject
                an id that already exists — use the chain viewer's re-synthesise
                button instead.
              </div>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="manual-cvss">CVSS score</label>
              <input
                id="manual-cvss"
                className={`input mono${!cvssValid ? " invalid" : ""}`}
                type="number"
                min={0}
                max={10}
                step="0.1"
                placeholder="9.8"
                value={cvssScore}
                onChange={(e) => setCvssScore(e.target.value)}
              />
              <div className="form-hint">Optional. 0.0 – 10.0.</div>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="manual-cvss-vec">CVSS vector</label>
              <input
                id="manual-cvss-vec"
                className="input mono"
                placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                value={cvssVector}
                onChange={(e) => setCvssVector(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="manual-tlp">TLP</label>
              <Dropdown<TlpLevel>
                value={tlp}
                onChange={(v) => setTlp(v ?? "tlp:clear")}
                options={[
                  { value: "tlp:clear", label: "TLP:CLEAR" },
                  { value: "tlp:green", label: "TLP:GREEN" },
                  { value: "tlp:amber", label: "TLP:AMBER" },
                  { value: "tlp:amber+strict", label: "TLP:AMBER+STRICT" },
                  { value: "tlp:red", label: "TLP:RED" },
                ]}
              />
            </div>

            <div className="form-group manual-cve-kev">
              <label className="form-label" htmlFor="manual-kev">
                <input
                  id="manual-kev"
                  type="checkbox"
                  checked={cisaKev}
                  onChange={(e) => setCisaKev(e.target.checked)}
                />
                CISA KEV
              </label>
              <div className="form-hint">
                Bumps priority score on any generated rule.
              </div>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="manual-products">Affected products</label>
              <input
                id="manual-products"
                className="input mono"
                placeholder="apache:streamflow, microsoft:windows"
                value={productsText}
                onChange={(e) => setProductsText(e.target.value)}
              />
              <div className="form-hint">
                <code className="mono">vendor:product</code> entries, comma-separated.
              </div>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="manual-desc">
              Description / advisory text
              <span className={`manual-cve-counter${descriptionValid ? "" : " low"}`}>
                {descriptionLen} / {DESCRIPTION_MAX} chars
                {descriptionLen < DESCRIPTION_MIN && ` · ${DESCRIPTION_MIN - descriptionLen} more needed`}
              </span>
            </label>
            <textarea
              id="manual-desc"
              className="textarea mono"
              rows={12}
              placeholder={"Paste the advisory body here. Markdown OK. The LLM uses this as the primary evidence source — the more concrete the better (CVE summary, affected versions, exploit primitive, observed-in-the-wild notes, mitigations)."}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              spellCheck={false}
            />
            <div className="form-hint">
              The synth prompt forbids the LLM from inventing source URLs.
              Anything you want cited per-TTP must be listed in the
              References section below.
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">
              References
              <span className="manual-cve-counter">
                {references.filter((r) => r.trim()).length} / {REF_MAX}
              </span>
            </label>
            {references.map((url, idx) => (
              <div key={idx} className="manual-cve-ref-row">
                <input
                  className="input mono"
                  type="url"
                  placeholder="https://vendor.example.com/advisories/abc-1234"
                  value={url}
                  onChange={(e) => updateRef(idx, e.target.value)}
                />
                <button
                  type="button"
                  className="btn sm ghost"
                  onClick={() => removeRefField(idx)}
                  aria-label={`Remove reference ${idx + 1}`}
                >
                  ×
                </button>
              </div>
            ))}
            <button
              type="button"
              className="btn sm ghost"
              onClick={addRefField}
              disabled={references.length >= REF_MAX}
            >
              + Add reference URL
            </button>
            <div className="form-hint">
              At least one reference is recommended — the chain prompt
              requires every TTP to cite a source. With zero references the
              LLM may refuse to produce a chain (the prompt's anti-
              hallucination rule).
            </div>
          </div>

          {error && (
            <div className="dashboard-banner danger">
              <span>{error}</span>
            </div>
          )}

          <div className="manual-cve-actions">
            <div className="manual-cve-summary text-sm text-dim">
              {canSubmit ? (
                <>
                  Ready to submit. Pipeline will run automatically; redirects to{" "}
                  <code className="mono">/chains/{cveIdNormalized}</code> on success.
                </>
              ) : !cveIdValid ? (
                "Enter a valid CVE id."
              ) : !descriptionValid ? (
                `Description needs ${DESCRIPTION_MIN}–${DESCRIPTION_MAX} chars.`
              ) : !cvssValid ? (
                "CVSS score must be between 0 and 10."
              ) : (
                "Submitting…"
              )}
            </div>
            <div className="manual-cve-action-buttons">
              <button
                type="button"
                className="btn ghost"
                onClick={() => navigate(-1)}
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn active"
                disabled={!canSubmit}
              >
                {submitting ? <Spinner /> : "Submit + analyze"}
              </button>
            </div>
          </div>
        </form>
      </div>

      <div className="card manual-cve-info">
        <div className="card-header">
          <div className="card-title">What happens next</div>
        </div>
        <ol className="manual-cve-steps">
          <li>
            <Badge variant="accent">1</Badge>
            <div>
              <strong>Synthesize.</strong> Claude (via LiteLLM) reads your
              description + references and produces an ordered ATT&CK chain.
              Schema-validated, retried up to 3× on errors.
            </div>
          </li>
          <li>
            <Badge variant="accent">2</Badge>
            <div>
              <strong>Map coverage.</strong> Each TTP is checked against the
              imported Sigma rules. Anything uncovered becomes a gap.
            </div>
          </li>
          <li>
            <Badge variant="accent">3</Badge>
            <div>
              <strong>Generate rules.</strong> For each gap, the rule generator
              produces one Sigma rule per enabled logsource profile (linux-auditd,
              windows-security by default). pySigma validates each.
            </div>
          </li>
          <li>
            <Badge variant="accent">4</Badge>
            <div>
              <strong>Review queue.</strong> Generated rules land at status
              <code className="mono"> generated</code> with priority based on
              KEV / CVSS / EPSS. Open <code className="mono">/queue</code> to
              approve, edit, or reject.
            </div>
          </li>
        </ol>
      </div>
    </div>
  );
}
