import { useCallback, useEffect, useMemo, useState } from "react";
import CodeMirror, { type Extension } from "@uiw/react-codemirror";
import { oneDark } from "@codemirror/theme-one-dark";
import { EditorView } from "@codemirror/view";

import {
  Badge,
  Dropdown,
  type DropdownOption,
  EmptyState,
  FirstRunHint,
  Modal,
  Spinner,
  useToast,
} from "../components";
import { detailFromError } from "../api/client";
import {
  type ABTest,
  type BenchmarkSummary,
  type CreateABTestBody,
  type CreatePromptBody,
  type DiffResponse,
  type PromptTemplate,
  type PromptTemplateDetail,
  WILDCARD,
  activatePrompt,
  concludeAbTest,
  createAbTest,
  createPrompt,
  diffPrompts,
  evaluatePrompt,
  getPrompt,
  listAbTests,
  listBenchmarks,
  listPrompts,
  updatePrompt,
} from "../api/prompts";

const TEXT_EXTENSIONS: Extension[] = [oneDark, EditorView.lineWrapping];

type GroupKey = string;

interface Group {
  key: GroupKey;
  task_type: string;
  target_model: string;
  target_provider: string;
  versions: PromptTemplate[];
}

function groupKey(p: PromptTemplate): GroupKey {
  return `${p.task_type}::${p.target_model}::${p.target_provider}`;
}

function describeGroup(g: Group): string {
  const m = g.target_model === WILDCARD ? "any model" : g.target_model;
  const pr = g.target_provider === WILDCARD ? "any provider" : g.target_provider;
  return `${m} · ${pr}`;
}

export function Prompts() {
  const [templates, setTemplates] = useState<PromptTemplate[]>([]);
  const [tests, setTests] = useState<ABTest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [newTemplateOpen, setNewTemplateOpen] = useState(false);
  const [newAbOpen, setNewAbOpen] = useState(false);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [t, ab] = await Promise.all([listPrompts(), listAbTests()]);
      setTemplates(t.templates);
      setTests(ab);
      if (!selectedId && t.templates.length > 0) {
        setSelectedId(t.templates[0].id);
      }
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, [selectedId]);

  useEffect(() => {
    void loadAll();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const groups = useMemo<Group[]>(() => {
    const m = new Map<GroupKey, Group>();
    for (const t of templates) {
      const k = groupKey(t);
      const existing = m.get(k);
      if (existing) {
        existing.versions.push(t);
      } else {
        m.set(k, {
          key: k,
          task_type: t.task_type,
          target_model: t.target_model,
          target_provider: t.target_provider,
          versions: [t],
        });
      }
    }
    // versions already arrive desc-by-version from backend; reassert.
    for (const g of m.values()) {
      g.versions.sort((a, b) => b.version - a.version);
    }
    return Array.from(m.values()).sort((a, b) =>
      a.task_type.localeCompare(b.task_type),
    );
  }, [templates]);

  const selectedTemplate = templates.find((t) => t.id === selectedId) ?? null;

  return (
    <div className="prompts-shell">
      <aside className="card prompts-list-card">
        <div className="card-header">
          <div className="card-title">Templates</div>
          <button className="btn sm active" onClick={() => setNewTemplateOpen(true)}>
            + New
          </button>
        </div>

        {error && (
          <div className="dashboard-banner danger">
            <span>{error}</span>
            <button className="btn sm" onClick={() => void loadAll()}>Retry</button>
          </div>
        )}

        {loading && templates.length === 0 ? (
          <Spinner />
        ) : groups.length === 0 ? (
          <FirstRunHint
            title="No prompt templates loaded"
            message="Chain synthesis and rule generation need active prompt templates. Run the setup script in your repo root to load the built-in chain / rule / coverage prompts, or click 'New template' to author your own."
            command="./setup.sh"
            note="Without active prompts, the synthesis pipeline will fail with 'No active chain_generation prompt template'."
          />
        ) : (
          groups.map((g) => (
            <div key={g.key}>
              <div className="prompts-group-header">
                {g.task_type}
                <div className="text-xs" style={{ textTransform: "none", letterSpacing: 0 }}>
                  {describeGroup(g)}
                </div>
              </div>
              {g.versions.map((v) => (
                <button
                  key={v.id}
                  type="button"
                  className={`prompt-list-item${selectedId === v.id ? " active" : ""}`}
                  onClick={() => setSelectedId(v.id)}
                >
                  <span className="prompt-list-item-name">{v.name}</span>
                  <span className="prompt-list-item-meta">
                    v{v.version}
                    {v.is_active && (
                      <span style={{ marginLeft: 4 }}>
                        <Badge variant="success">active</Badge>
                      </span>
                    )}
                  </span>
                </button>
              ))}
            </div>
          ))
        )}
      </aside>

      <div className="prompts-detail-shell">
        {selectedTemplate ? (
          <PromptDetail
            templateId={selectedTemplate.id}
            siblings={
              groups.find((g) => groupKey(selectedTemplate) === g.key)?.versions ?? []
            }
            onChanged={loadAll}
          />
        ) : (
          <div className="card">
            <EmptyState
              title="No prompt selected"
              hint="Pick a template from the list to view, edit, evaluate, or compare versions."
            />
          </div>
        )}

        <ABTestsCard
          tests={tests}
          templates={templates}
          onOpenNewAb={() => setNewAbOpen(true)}
          onChanged={loadAll}
        />
      </div>

      {newTemplateOpen && (
        <NewTemplateModal
          onClose={() => setNewTemplateOpen(false)}
          onCreated={async (t) => {
            setNewTemplateOpen(false);
            setSelectedId(t.id);
            await loadAll();
          }}
        />
      )}

      {newAbOpen && (
        <NewABTestModal
          templates={templates}
          onClose={() => setNewAbOpen(false)}
          onCreated={async () => {
            setNewAbOpen(false);
            await loadAll();
          }}
        />
      )}
    </div>
  );
}

interface PromptDetailProps {
  templateId: string;
  siblings: PromptTemplate[];
  onChanged: () => Promise<void>;
}

function PromptDetail({ templateId, siblings, onChanged }: PromptDetailProps) {
  const toast = useToast();
  const [detail, setDetail] = useState<PromptTemplateDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [systemText, setSystemText] = useState("");
  const [userText, setUserText] = useState("");
  const [notesText, setNotesText] = useState("");
  const [dirty, setDirty] = useState(false);
  const [savingPatch, setSavingPatch] = useState(false);
  const [activating, setActivating] = useState(false);

  const [compareId, setCompareId] = useState<string | null>(null);
  const [diff, setDiff] = useState<DiffResponse | null>(null);
  const [diffOpen, setDiffOpen] = useState(false);
  const [diffLoading, setDiffLoading] = useState(false);

  const [evalOpen, setEvalOpen] = useState(false);
  const [benchmarks, setBenchmarks] = useState<BenchmarkSummary[]>([]);
  const [selectedBench, setSelectedBench] = useState<string>("");
  const [runningEval, setRunningEval] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await getPrompt(templateId);
      setDetail(d);
      setSystemText(d.system_prompt);
      setUserText(d.user_template);
      setNotesText(d.notes ?? "");
      setDirty(false);
    } catch (err) {
      setError(detailFromError(err));
    } finally {
      setLoading(false);
    }
  }, [templateId]);

  useEffect(() => {
    void load();
  }, [load]);

  const openEval = async () => {
    setEvalOpen(true);
    if (benchmarks.length > 0) return;
    try {
      const r = await listBenchmarks();
      setBenchmarks(r);
      if (r.length > 0) setSelectedBench(r[0].name);
    } catch (err) {
      toast.error(detailFromError(err), "Could not load benchmarks");
    }
  };

  const runEval = async () => {
    if (!detail || !selectedBench) return;
    setRunningEval(true);
    try {
      const r = await evaluatePrompt(detail.id, { benchmark_set: selectedBench });
      toast.success(
        `Overlap ${r.technique_overlap?.toFixed(2) ?? "—"} · halluc ${r.hallucination_count ?? "—"} · $${r.cost_per_run?.toFixed(4) ?? "—"} · ${r.avg_latency_ms ?? "—"}ms`,
        `Eval · ${selectedBench}`,
      );
      setEvalOpen(false);
      await load();
    } catch (err) {
      toast.error(detailFromError(err), "Evaluation failed");
    } finally {
      setRunningEval(false);
    }
  };

  const openDiff = async (otherId: string) => {
    if (!detail) return;
    setCompareId(otherId);
    setDiffOpen(true);
    setDiffLoading(true);
    setDiff(null);
    try {
      const d = await diffPrompts(detail.id, otherId);
      setDiff(d);
    } catch (err) {
      toast.error(detailFromError(err), "Diff failed");
    } finally {
      setDiffLoading(false);
    }
  };

  const saveAsNewVersion = async () => {
    if (!detail) return;
    setSavingPatch(true);
    try {
      const fresh = await updatePrompt(detail.id, {
        system_prompt: systemText,
        user_template: userText,
        notes: notesText || null,
        activate: false,
      });
      toast.success(`Saved as version ${fresh.version}.`);
      setDirty(false);
      await onChanged();
    } catch (err) {
      toast.error(detailFromError(err), "Save failed");
    } finally {
      setSavingPatch(false);
    }
  };

  const handleActivate = async () => {
    if (!detail) return;
    setActivating(true);
    try {
      await activatePrompt(detail.id);
      toast.success("Activated.");
      await Promise.all([load(), onChanged()]);
    } catch (err) {
      toast.error(detailFromError(err), "Activate failed");
    } finally {
      setActivating(false);
    }
  };

  if (loading && !detail) {
    return <div className="card"><Spinner /></div>;
  }

  if (error) {
    return (
      <div className="card">
        <div className="dashboard-banner danger">
          <span>{error}</span>
          <button className="btn sm" onClick={() => void load()}>Retry</button>
        </div>
      </div>
    );
  }

  if (!detail) return null;

  const otherVersions = siblings.filter((s) => s.id !== detail.id);
  const versionOptions: DropdownOption<string>[] = otherVersions.map((s) => ({
    value: s.id,
    label: `v${s.version}${s.is_active ? " (active)" : ""}`,
  }));

  return (
    <>
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              {detail.name}
              <span className="text-dim text-xs mono" style={{ marginLeft: 8 }}>
                v{detail.version}
              </span>
              {detail.is_active && (
                <span style={{ marginLeft: 8 }}>
                  <Badge variant="success">active</Badge>
                </span>
              )}
            </div>
            <div className="text-xs text-dim mono">
              {detail.task_type} · {detail.target_model} · {detail.target_provider}
              {detail.created_by && ` · by ${detail.created_by}`} · {detail.created_at}
            </div>
          </div>
          <div className="settings-row-actions">
            {!detail.is_active && (
              <button
                className="btn active sm"
                onClick={() => void handleActivate()}
                disabled={activating}
              >
                {activating ? "…" : "Activate"}
              </button>
            )}
            <button className="btn sm ghost" onClick={() => void openEval()}>
              Run eval
            </button>
            <button
              className="btn sm ghost"
              onClick={() => void saveAsNewVersion()}
              disabled={!dirty || savingPatch}
            >
              {savingPatch ? "Saving…" : "Save as new version"}
            </button>
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">System prompt</label>
          <div className="prompt-editor">
            <CodeMirror
              value={systemText}
              theme={oneDark}
              extensions={TEXT_EXTENSIONS}
              onChange={(text) => {
                setSystemText(text);
                setDirty(true);
              }}
            />
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">User template</label>
          <div className="prompt-editor">
            <CodeMirror
              value={userText}
              theme={oneDark}
              extensions={TEXT_EXTENSIONS}
              onChange={(text) => {
                setUserText(text);
                setDirty(true);
              }}
            />
          </div>
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="prompt-notes">Notes</label>
          <textarea
            id="prompt-notes"
            className="textarea"
            rows={2}
            value={notesText}
            onChange={(e) => {
              setNotesText(e.target.value);
              setDirty(true);
            }}
          />
        </div>

        {otherVersions.length > 0 && (
          <div className="form-group">
            <label className="form-label">Compare with another version</label>
            <div style={{ display: "flex", gap: "var(--space-2)" }}>
              <Dropdown
                options={versionOptions}
                value={compareId}
                onChange={(v) => setCompareId(v)}
                placeholder="Choose version…"
              />
              <button
                className="btn ghost"
                disabled={!compareId}
                onClick={() => compareId && void openDiff(compareId)}
              >
                Open diff
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-title">Evaluations</div>
        {detail.evaluations.length === 0 ? (
          <EmptyState
            title="No evaluations yet"
            hint="Run an evaluation to score this prompt against a benchmark fixture."
          />
        ) : (
          <table className="eval-table">
            <thead>
              <tr>
                <th>Benchmark</th>
                <th>Overlap</th>
                <th>Ordering</th>
                <th>Halluc</th>
                <th>Cost ($)</th>
                <th>Latency</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {detail.evaluations.map((e) => (
                <tr key={e.id}>
                  <td>{e.benchmark_set}</td>
                  <td>{e.technique_overlap?.toFixed(2) ?? "—"}</td>
                  <td>{e.ordering_consistency?.toFixed(2) ?? "—"}</td>
                  <td>{e.hallucination_count ?? "—"}</td>
                  <td>{e.cost_per_run?.toFixed(4) ?? "—"}</td>
                  <td>{e.avg_latency_ms != null ? `${e.avg_latency_ms}ms` : "—"}</td>
                  <td>{e.evaluated_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {diffOpen && (
        <DiffModal
          open
          loading={diffLoading}
          diff={diff}
          onClose={() => {
            setDiffOpen(false);
            setDiff(null);
          }}
        />
      )}

      <Modal
        open={evalOpen}
        onClose={runningEval ? () => undefined : () => setEvalOpen(false)}
        title="Run evaluation"
        footer={
          <>
            <button
              className="btn ghost"
              onClick={() => setEvalOpen(false)}
              disabled={runningEval}
            >
              Cancel
            </button>
            <button
              className="btn active"
              onClick={() => void runEval()}
              disabled={runningEval || !selectedBench}
            >
              {runningEval ? "Running…" : "Run"}
            </button>
          </>
        }
      >
        {benchmarks.length === 0 ? (
          <Spinner />
        ) : (
          <div className="form-group">
            <label className="form-label">Benchmark set</label>
            <Dropdown
              options={benchmarks.map((b) => ({
                value: b.name,
                label: `${b.name} (${b.case_count} cases × ${b.iterations_per_case})`,
              }))}
              value={selectedBench}
              onChange={(v) => setSelectedBench(v ?? "")}
            />
            {benchmarks.find((b) => b.name === selectedBench)?.description && (
              <div className="form-hint">
                {benchmarks.find((b) => b.name === selectedBench)?.description}
              </div>
            )}
          </div>
        )}
      </Modal>
    </>
  );
}

interface DiffModalProps {
  open: boolean;
  loading: boolean;
  diff: DiffResponse | null;
  onClose: () => void;
}

function DiffModal({ open, loading, diff, onClose }: DiffModalProps) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      wide
      title="Version diff"
      footer={<button className="btn ghost" onClick={onClose}>Close</button>}
    >
      {loading ? (
        <Spinner />
      ) : !diff ? (
        <EmptyState title="No diff loaded" />
      ) : (
        <>
          <div className="form-label">System prompt</div>
          <DiffBlock lines={diff.system_prompt_diff} />
          <div className="form-label" style={{ marginTop: "var(--space-3)" }}>
            User template
          </div>
          <DiffBlock lines={diff.user_template_diff} />
        </>
      )}
    </Modal>
  );
}

function DiffBlock({ lines }: { lines: string[] }) {
  if (lines.length === 0) {
    return <div className="text-sm text-dim">No differences.</div>;
  }
  return (
    <div className="prompt-diff-card">
      {lines.map((line, idx) => {
        const cls = line.startsWith("+")
          ? "diff-line add"
          : line.startsWith("-")
            ? "diff-line remove"
            : line.startsWith("@@")
              ? "diff-line hunk"
              : "diff-line";
        return (
          <div key={idx} className={cls}>
            {line || " "}
          </div>
        );
      })}
    </div>
  );
}

interface NewTemplateModalProps {
  onClose: () => void;
  onCreated: (t: PromptTemplate) => Promise<void>;
}

function NewTemplateModal({ onClose, onCreated }: NewTemplateModalProps) {
  const toast = useToast();
  const [form, setForm] = useState<CreatePromptBody>({
    name: "",
    task_type: "chain_generation",
    system_prompt: "",
    user_template: "",
    target_model: WILDCARD,
    target_provider: WILDCARD,
    notes: null,
    activate: false,
  });
  const [saving, setSaving] = useState(false);

  const set = <K extends keyof CreatePromptBody>(key: K, value: CreatePromptBody[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const submit = async () => {
    setSaving(true);
    try {
      const created = await createPrompt(form);
      toast.success(`${created.name} v${created.version} created.`);
      await onCreated(created);
    } catch (err) {
      toast.error(detailFromError(err), "Create failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={saving ? () => undefined : onClose}
      wide
      title="New prompt template"
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="btn active"
            onClick={() => void submit()}
            disabled={
              saving ||
              !form.name.trim() ||
              !form.task_type.trim() ||
              !form.system_prompt.trim() ||
              !form.user_template.trim()
            }
          >
            {saving ? "Creating…" : "Create"}
          </button>
        </>
      }
    >
      <div className="settings-form-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="np-name">Name</label>
          <input
            id="np-name"
            className="input"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="np-task">Task type</label>
          <input
            id="np-task"
            className="input mono"
            value={form.task_type}
            onChange={(e) => set("task_type", e.target.value)}
            placeholder="chain_generation"
          />
          <div className="form-hint">
            Seed task types: chain_generation, rule_generation, coverage_verify.
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="np-model">Target model</label>
          <input
            id="np-model"
            className="input mono"
            value={form.target_model ?? WILDCARD}
            onChange={(e) => set("target_model", e.target.value)}
            placeholder="* (any model)"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="np-provider">Target provider</label>
          <input
            id="np-provider"
            className="input mono"
            value={form.target_provider ?? WILDCARD}
            onChange={(e) => set("target_provider", e.target.value)}
            placeholder="* (any provider)"
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="np-system">System prompt</label>
          <textarea
            id="np-system"
            className="textarea mono"
            rows={6}
            value={form.system_prompt}
            onChange={(e) => set("system_prompt", e.target.value)}
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="np-user">User template</label>
          <textarea
            id="np-user"
            className="textarea mono"
            rows={6}
            value={form.user_template}
            onChange={(e) => set("user_template", e.target.value)}
          />
        </div>
        <div className="form-group span-2">
          <label className="form-label" htmlFor="np-notes">Notes</label>
          <textarea
            id="np-notes"
            className="textarea"
            rows={2}
            value={form.notes ?? ""}
            onChange={(e) => set("notes", e.target.value || null)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Activate immediately</label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={!!form.activate}
              onChange={(e) => set("activate", e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
          <div className="form-hint">
            Deactivates the current active version for the same (task, model, provider) key.
          </div>
        </div>
      </div>
    </Modal>
  );
}

interface ABTestsCardProps {
  tests: ABTest[];
  templates: PromptTemplate[];
  onOpenNewAb: () => void;
  onChanged: () => Promise<void>;
}

function ABTestsCard({ tests, templates, onOpenNewAb, onChanged }: ABTestsCardProps) {
  const toast = useToast();
  const [working, setWorking] = useState<string | null>(null);

  const templateLabel = (id: string): string => {
    const t = templates.find((x) => x.id === id);
    if (!t) return id.slice(0, 8);
    return `${t.name} v${t.version}`;
  };

  const handleConclude = async (test: ABTest, winner: "A" | "B" | null) => {
    setWorking(test.id);
    try {
      await concludeAbTest(test.id, { winner });
      toast.success(`Concluded — winner: ${winner ?? "tie"}`);
      await onChanged();
    } catch (err) {
      toast.error(detailFromError(err), "Conclude failed");
    } finally {
      setWorking(null);
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">A/B Tests</div>
        <button className="btn active sm" onClick={onOpenNewAb}>
          + New A/B test
        </button>
      </div>
      {tests.length === 0 ? (
        <EmptyState
          title="No A/B tests"
          hint="Start an A/B test to route traffic between two prompt versions and pick a winner empirically."
        />
      ) : (
        tests.map((t) => {
          const active = t.status === "active";
          return (
            <div className="ab-row" key={t.id}>
              <div>
                <div className="ab-row-name">{t.name}</div>
                <div className="ab-row-meta">
                  {t.task_type} · split {Math.round((t.traffic_split ?? 0) * 100)}/{100 - Math.round((t.traffic_split ?? 0) * 100)}
                </div>
                <div className="ab-row-meta">
                  A: {templateLabel(t.variant_a_template_id)} · B:{" "}
                  {templateLabel(t.variant_b_template_id)}
                </div>
              </div>
              <Badge variant={active ? "accent" : "default"}>{t.status}</Badge>
              {t.winner && (
                <Badge variant="success">winner {t.winner}</Badge>
              )}
              {active ? (
                <div className="settings-row-actions">
                  <button
                    className="btn sm"
                    disabled={working === t.id}
                    onClick={() => void handleConclude(t, "A")}
                  >
                    Pick A
                  </button>
                  <button
                    className="btn sm"
                    disabled={working === t.id}
                    onClick={() => void handleConclude(t, "B")}
                  >
                    Pick B
                  </button>
                  <button
                    className="btn sm ghost"
                    disabled={working === t.id}
                    onClick={() => void handleConclude(t, null)}
                  >
                    End (tie)
                  </button>
                </div>
              ) : (
                <span className="text-xs text-dim mono">
                  {t.concluded_at ?? "—"}
                </span>
              )}
            </div>
          );
        })
      )}
    </div>
  );
}

interface NewABTestModalProps {
  templates: PromptTemplate[];
  onClose: () => void;
  onCreated: () => Promise<void>;
}

function NewABTestModal({ templates, onClose, onCreated }: NewABTestModalProps) {
  const toast = useToast();
  const [form, setForm] = useState<CreateABTestBody>({
    name: "",
    task_type: templates[0]?.task_type ?? "chain_generation",
    variant_a_template_id: templates[0]?.id ?? "",
    variant_b_template_id: templates[1]?.id ?? "",
    traffic_split: 0.5,
  });
  const [saving, setSaving] = useState(false);

  const set = <K extends keyof CreateABTestBody>(key: K, value: CreateABTestBody[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const taskTypeOptions = useMemo<DropdownOption<string>[]>(() => {
    const seen = new Set<string>();
    const out: DropdownOption<string>[] = [];
    for (const t of templates) {
      if (!seen.has(t.task_type)) {
        seen.add(t.task_type);
        out.push({ value: t.task_type, label: t.task_type });
      }
    }
    return out;
  }, [templates]);

  const variantOptions = useMemo<DropdownOption<string>[]>(
    () =>
      templates
        .filter((t) => t.task_type === form.task_type)
        .map((t) => ({
          value: t.id,
          label: `${t.name} v${t.version}${t.is_active ? " (active)" : ""}`,
        })),
    [templates, form.task_type],
  );

  const submit = async () => {
    setSaving(true);
    try {
      const t = await createAbTest(form);
      toast.success(`A/B test "${t.name}" started.`);
      await onCreated();
    } catch (err) {
      toast.error(detailFromError(err), "Create failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={saving ? () => undefined : onClose}
      title="Start A/B test"
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="btn active"
            onClick={() => void submit()}
            disabled={
              saving ||
              !form.name.trim() ||
              !form.task_type.trim() ||
              !form.variant_a_template_id ||
              !form.variant_b_template_id ||
              form.variant_a_template_id === form.variant_b_template_id
            }
          >
            {saving ? "Starting…" : "Start"}
          </button>
        </>
      }
    >
      <div className="form-group">
        <label className="form-label" htmlFor="ab-name">Name</label>
        <input
          id="ab-name"
          className="input"
          value={form.name}
          onChange={(e) => set("name", e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Task type</label>
        <Dropdown
          options={taskTypeOptions}
          value={form.task_type}
          onChange={(v) => set("task_type", v ?? "")}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Variant A</label>
        <Dropdown
          options={variantOptions}
          value={form.variant_a_template_id}
          onChange={(v) => set("variant_a_template_id", v ?? "")}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Variant B</label>
        <Dropdown
          options={variantOptions}
          value={form.variant_b_template_id}
          onChange={(v) => set("variant_b_template_id", v ?? "")}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor="ab-split">
          Traffic split (fraction sent to variant A)
        </label>
        <input
          id="ab-split"
          className="input mono"
          type="number"
          min={0}
          max={1}
          step={0.05}
          value={form.traffic_split ?? 0.5}
          onChange={(e) =>
            set("traffic_split", Math.max(0, Math.min(1, Number(e.target.value) || 0)))
          }
        />
      </div>
    </Modal>
  );
}
