# W2c Detectability Benchmark Implementation Plan (Phase 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build (zero LLM spend) a standalone benchmark harness that scores the `DetectabilityClassifier` against curated, owner-adjudicatable fixtures — `predict()` refactor + pure metrics module + 30-case fixture + runner with `--dry-run` + adjudication doc + tests.

**Architecture:** Split the classifier's LLM prediction from its DB persistence (`predict()`), so a benchmark can call it without writing rows. A pure metrics module computes 5-class accuracy / per-class P-R-F1 / confusion matrix / confidence calibration. A fixture JSON holds 30 curated `(loop2_output, gate_result, expected_class)` cases. A runner drives `predict()` per case, computes metrics, and (in the scored Phase 3) persists one `prompt_evaluations` row (JSONB report). `--dry-run` validates fixtures + runs metrics on labels with no LLM/DB — that's the CI-testable path.

**Tech Stack:** Python 3.12 async, SQLAlchemy 2.0, Pydantic v2, pytest, structlog.

**Spec:** [docs/superpowers/specs/2026-06-13-w2c-detectability-benchmark-design.md](../specs/2026-06-13-w2c-detectability-benchmark-design.md)

**Environment:** Worktree `<repo-root>/.claude/worktrees/wave2c-benchmark`, branch `claude/wave2c-detectability-benchmark`. Run tests with `.venv/bin/python -m pytest <args>` from the worktree root (controller pre-builds the venv). Zero LLM spend in this plan — no task runs the real classifier.

**Verified facts (against the code):**
- `LoopContext` (`fragchain/assessments/loops/base.py:18`): dataclass with `assessment_id: uuid.UUID`, `cve_id: uuid.UUID`, `cve_textual_id: str`, `source_contents: list[str]`, `prior_outputs: dict[int, dict[str, Any]]`.
- `DetectabilityClass` enum values: `directly_detectable`, `indirectly_detectable`, `environment_dependent`, `control_only`, `insufficient_information`.
- `DetectabilityAssessment` (pydantic): `detectability_class: DetectabilityClass`, `confidence: float (0..1)`, + more fields.
- `ObservableCategory` (`fragchain/assessments/loops/schemas.py:15`): `process, command_line, file, network, registry, parent_child, api_call`.
- `StructuredResult` (`fragchain/llm/structured.py:61`): `value`, `cost_usd: float`.
- `_classify` reads `ctx.cve_textual_id`, `ctx.prior_outputs.get(1)["vuln_profile"]`, `loop2_output["indicators"]`/`["unanswered_questions"]`, `gate_result`; calls `structured_complete(... schema=DetectabilityAssessment ...)`; builds `DetectabilityAssessmentRow` from `result.value` + `model` + `result.cost_usd` + `selection.id`; `session.add(row)`.
- Existing classifier tests (`tests/assessments/test_detectability_classifier.py`) patch `fragchain.assessments.detectability.structured_complete` with an `AsyncMock` returning a `StructuredResult(value=_assessment_value(), confidence=1.0)`; `test_classify_persists_row`, `test_classify_failure_returns_none_never_raises`.

---

## Task 1: `predict()` extraction (behavior-preserving refactor)

**Files:**
- Modify: `fragchain/assessments/detectability.py` (`DetectabilityClassifier`)
- Test: `tests/assessments/test_detectability_classifier.py`

- [ ] **Step 1: Capture the green baseline**

Run: `.venv/bin/python -m pytest tests/assessments/test_detectability_classifier.py -q`
Record the pass count — it must not drop.

- [ ] **Step 2: Write the new failing test**

Append to `tests/assessments/test_detectability_classifier.py` (reuse the file's existing `_assessment_value()` helper, `_ctx()`/context builder, and the `structured_complete` patch pattern already in the file — read them first and mirror exactly):

```python
@pytest.mark.asyncio
async def test_predict_returns_assessment_and_does_not_persist() -> None:
    session = MagicMock()
    session.add = MagicMock()
    clf = _make_classifier(session)  # use the file's existing classifier-construction helper
    fake = StructuredResult(value=_assessment_value(), confidence=1.0, cost_usd=0.01)
    with patch(
        "fragchain.assessments.detectability.structured_complete",
        AsyncMock(return_value=fake),
    ), patch.object(
        clf._prompt_store, "get_active", AsyncMock(return_value=_fake_selection())
    ):
        result = await clf.predict(
            ctx=_ctx(),
            loop2_output={"indicators": {"network": [{"value": "x"}]}, "unanswered_questions": []},
            gate_result={"passed": True, "filled_categories": ["network"], "empty_categories": [], "threshold": 3},
        )
    assert result.assessment.detectability_class is not None
    assert isinstance(result.cost_usd, float)
    session.add.assert_not_called()  # predict must NOT persist
```

Adapt `_make_classifier`, `_ctx`, `_fake_selection` to the actual helpers in the file (the existing `test_classify_persists_row` already constructs all three — copy its setup). If the file inlines them, inline the same here.

- [ ] **Step 3: Run, confirm fail**

Run: `.venv/bin/python -m pytest tests/assessments/test_detectability_classifier.py::test_predict_returns_assessment_and_does_not_persist -v`
Expected: FAIL — `AttributeError: 'DetectabilityClassifier' object has no attribute 'predict'`.

- [ ] **Step 4: Implement `predict()` + refactor `_classify`**

In `fragchain/assessments/detectability.py`, add a result dataclass near the top (after imports):

```python
from dataclasses import dataclass

@dataclass
class PredictResult:
    assessment: "DetectabilityAssessment"
    model: str
    cost_usd: float
    prompt_template_id: uuid.UUID
```

Add the `predict` method to `DetectabilityClassifier` — move the prompt-building + `structured_complete` call out of `_classify` verbatim:

```python
    async def predict(
        self,
        *,
        ctx: LoopContext,
        loop2_output: dict[str, Any],
        gate_result: dict[str, Any],
    ) -> PredictResult:
        selection = await self._prompt_store.get_active(
            task_type="detectability_classification",
            target_model=self._model_override or "*",
            target_provider="*",
        )
        loop1_out = ctx.prior_outputs.get(1) or {}
        vuln_profile = loop1_out.get("vuln_profile") or {}
        indicators = loop2_output.get("indicators") or {}
        unanswered = loop2_output.get("unanswered_questions") or []
        gate_summary = (
            f"passed={gate_result.get('passed')}, "
            f"filled={gate_result.get('filled_categories')}, "
            f"empty={gate_result.get('empty_categories')}, "
            f"threshold={gate_result.get('threshold')}"
        )
        user_text = selection.user_template.format(
            cve_id=ctx.cve_textual_id,
            vuln_profile=json.dumps(vuln_profile, indent=2, sort_keys=True),
            indicators_summary=_summarize_indicators(indicators),
            gate_summary=gate_summary,
            unanswered="\n".join(f"- {q}" for q in unanswered) or "(none)",
        )
        model = resolve_chat_model(self._model_override, selection.target_model)
        provider = resolve_chat_provider(self._provider)
        result = await structured_complete(
            provider=provider,
            system=selection.system_prompt,
            user=user_text,
            model=model,
            schema=DetectabilityAssessment,
            interaction_type=InteractionType.DETECTABILITY_CLASSIFICATION,
            entity_type="coverage_assessment",
            entity_id=ctx.assessment_id,
            prompt_template_id=selection.id,
            prompt_version=selection.version,
            timeout_seconds=get_settings().LLM_STRUCTURED_TIMEOUT_SECONDS,
        )
        return PredictResult(
            assessment=result.value,
            model=model,
            cost_usd=float(result.cost_usd),
            prompt_template_id=selection.id,
        )
```

Refactor `_classify` to delegate to `predict` then persist (behavior identical):

```python
    async def _classify(
        self,
        *,
        ctx: LoopContext,
        loop_run_id: uuid.UUID,
        loop2_output: dict[str, Any],
        gate_result: dict[str, Any],
    ) -> DetectabilityAssessmentRow:
        pr = await self.predict(
            ctx=ctx, loop2_output=loop2_output, gate_result=gate_result
        )
        assessment = pr.assessment
        row = DetectabilityAssessmentRow(
            assessment_id=ctx.assessment_id,
            loop_run_id=loop_run_id,
            detectability_class=assessment.detectability_class.value,
            confidence=Decimal(str(round(assessment.confidence, 3))),
            gate_passed=bool(gate_result.get("passed")),
            payload=assessment.model_dump(mode="json"),
            model=pr.model,
            prompt_template_id=pr.prompt_template_id,
            cost_usd=Decimal(str(round(pr.cost_usd, 4))),
        )
        self._session.add(row)
        logger.info(
            "assessment.detectability.classified",
            assessment_id=str(ctx.assessment_id),
            detectability_class=row.detectability_class,
        )
        return row
```

- [ ] **Step 5: Run the full classifier test file — must match baseline + the new test passes**

Run: `.venv/bin/python -m pytest tests/assessments/test_detectability_classifier.py -q`
Expected: Step-1 baseline count + 1 (the new test), all pass. If `test_classify_persists_row` breaks, your refactor changed behavior — diff the row construction and fix. Do NOT edit the existing tests.

Run `.venv/bin/ruff check fragchain/assessments/detectability.py` → clean.

- [ ] **Step 6: Commit**

```bash
git add fragchain/assessments/detectability.py tests/assessments/test_detectability_classifier.py
git commit -m "refactor(w2c): extract DetectabilityClassifier.predict() (no-persist prediction)"
```

---

## Task 2: Pure metrics module

**Files:**
- Create: `fragchain/evaluations/detectability_metrics.py`
- Create: `tests/evaluations/__init__.py` (if `tests/evaluations/` doesn't exist — check first)
- Create: `tests/evaluations/test_detectability_metrics.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/evaluations/test_detectability_metrics.py
"""Tests for the pure detectability-classification metrics."""
from __future__ import annotations

from fragchain.evaluations.detectability_metrics import CaseOutcome, compute_metrics


def _o(cid, exp, pred, conf):
    return CaseOutcome(case_id=cid, expected=exp, predicted=pred, confidence=conf)


def test_accuracy_and_n():
    res = compute_metrics([
        _o("a", "directly_detectable", "directly_detectable", 0.9),
        _o("b", "control_only", "control_only", 0.8),
        _o("c", "control_only", "directly_detectable", 0.7),
    ])
    assert res["n"] == 3
    assert res["accuracy"] == round(2 / 3, 4)


def test_per_class_precision_recall_f1():
    # directly_detectable: 1 TP, 1 FP (c predicted dd but was control_only), 0 FN
    res = compute_metrics([
        _o("a", "directly_detectable", "directly_detectable", 0.9),
        _o("c", "control_only", "directly_detectable", 0.7),
    ])
    dd = res["per_class"]["directly_detectable"]
    assert dd["precision"] == 0.5   # 1 TP / (1 TP + 1 FP)
    assert dd["recall"] == 1.0      # 1 TP / (1 TP + 0 FN)
    co = res["per_class"]["control_only"]
    assert co["recall"] == 0.0      # the one control_only case was misclassified
    assert co["precision"] is None  # 0 predicted control_only -> precision undefined


def test_confusion_matrix_shape_and_counts():
    res = compute_metrics([
        _o("a", "directly_detectable", "directly_detectable", 0.9),
        _o("c", "control_only", "directly_detectable", 0.7),
    ])
    classes = res["confusion_matrix"]["classes"]
    assert len(classes) == 5
    m = res["confusion_matrix"]["matrix"]
    di = classes.index("directly_detectable")
    ci = classes.index("control_only")
    assert m[di][di] == 1   # dd predicted dd
    assert m[ci][di] == 1   # control_only predicted dd
    # all rows length 5, total counts == n
    assert all(len(row) == 5 for row in m)
    assert sum(sum(row) for row in m) == 2


def test_calibration_correct_vs_incorrect():
    res = compute_metrics([
        _o("a", "directly_detectable", "directly_detectable", 0.9),  # correct
        _o("c", "control_only", "directly_detectable", 0.7),         # incorrect
    ])
    cal = res["calibration"]
    assert cal["mean_confidence"] == 0.8
    assert cal["mean_confidence_correct"] == 0.9
    assert cal["mean_confidence_incorrect"] == 0.7


def test_empty_input_is_safe():
    res = compute_metrics([])
    assert res["n"] == 0
    assert res["accuracy"] is None
```

- [ ] **Step 2: Run, confirm fail**

Run: `.venv/bin/python -m pytest tests/evaluations/test_detectability_metrics.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement the module**

```python
# fragchain/evaluations/detectability_metrics.py
"""Pure scoring for the detectability-classifier benchmark.

No LLM, no DB. Given per-case (expected, predicted, confidence) it computes
accuracy, per-class precision/recall/F1, a 5x5 confusion matrix, and a
confidence-calibration summary. Used by scripts/run_detectability_benchmark.py.
"""
from __future__ import annotations

from dataclasses import dataclass

from fragchain.assessments.detectability import DetectabilityClass

CLASS_ORDER: list[str] = [c.value for c in DetectabilityClass]


@dataclass
class CaseOutcome:
    case_id: str
    expected: str
    predicted: str
    confidence: float

    @property
    def correct(self) -> bool:
        return self.expected == self.predicted


def _round(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def compute_metrics(results: list[CaseOutcome]) -> dict:
    n = len(results)
    if n == 0:
        return {
            "n": 0,
            "accuracy": None,
            "macro_f1": None,
            "per_class": {c: {"precision": None, "recall": None, "f1": None, "support": 0} for c in CLASS_ORDER},
            "confusion_matrix": {"classes": CLASS_ORDER, "matrix": [[0] * len(CLASS_ORDER) for _ in CLASS_ORDER]},
            "calibration": {"mean_confidence": None, "mean_confidence_correct": None, "mean_confidence_incorrect": None},
        }

    correct = sum(1 for r in results if r.correct)
    accuracy = correct / n

    idx = {c: i for i, c in enumerate(CLASS_ORDER)}
    matrix = [[0] * len(CLASS_ORDER) for _ in CLASS_ORDER]
    for r in results:
        # Unknown labels (shouldn't happen post-fixture-validation) are skipped
        # from the matrix but still counted in n/accuracy.
        if r.expected in idx and r.predicted in idx:
            matrix[idx[r.expected]][idx[r.predicted]] += 1

    per_class: dict[str, dict] = {}
    f1s: list[float] = []
    for c in CLASS_ORDER:
        tp = sum(1 for r in results if r.expected == c and r.predicted == c)
        fp = sum(1 for r in results if r.expected != c and r.predicted == c)
        fn = sum(1 for r in results if r.expected == c and r.predicted != c)
        support = sum(1 for r in results if r.expected == c)
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall = tp / (tp + fn) if (tp + fn) > 0 else None
        if precision is not None and recall is not None and (precision + recall) > 0:
            f1: float | None = 2 * precision * recall / (precision + recall)
        elif (tp + fp) == 0 and (tp + fn) == 0:
            f1 = None  # class absent from both expected and predicted
        else:
            f1 = 0.0
        if f1 is not None:
            f1s.append(f1)
        per_class[c] = {
            "precision": _round(precision),
            "recall": _round(recall),
            "f1": _round(f1),
            "support": support,
        }

    macro_f1 = _round(sum(f1s) / len(f1s)) if f1s else None

    confs = [r.confidence for r in results]
    correct_confs = [r.confidence for r in results if r.correct]
    incorrect_confs = [r.confidence for r in results if not r.correct]
    calibration = {
        "mean_confidence": _round(sum(confs) / len(confs)) if confs else None,
        "mean_confidence_correct": _round(sum(correct_confs) / len(correct_confs)) if correct_confs else None,
        "mean_confidence_incorrect": _round(sum(incorrect_confs) / len(incorrect_confs)) if incorrect_confs else None,
    }

    return {
        "n": n,
        "accuracy": _round(accuracy),
        "macro_f1": macro_f1,
        "per_class": per_class,
        "confusion_matrix": {"classes": CLASS_ORDER, "matrix": matrix},
        "calibration": calibration,
    }
```

- [ ] **Step 4: Run, confirm pass**

Run: `.venv/bin/python -m pytest tests/evaluations/test_detectability_metrics.py -v`
Expected: 5 passed. Then `.venv/bin/ruff check fragchain/evaluations/detectability_metrics.py` → clean.

- [ ] **Step 5: Commit**

```bash
git add fragchain/evaluations/detectability_metrics.py tests/evaluations/
git commit -m "feat(w2c): pure detectability classification metrics module"
```

---

## Task 3: 30-case fixture + validation test

**Files:**
- Create: `benchmarks/detectability_pilot_v1.json`
- Create: `tests/evaluations/test_detectability_fixture.py`

- [ ] **Step 1: Write the failing validation test**

```python
# tests/evaluations/test_detectability_fixture.py
"""Structural validation of the detectability pilot fixture."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from fragchain.assessments.detectability import DetectabilityClass
from fragchain.assessments.loops.schemas import ObservableCategory

FIXTURE = Path(__file__).resolve().parents[2] / "benchmarks" / "detectability_pilot_v1.json"
VALID_CLASSES = {c.value for c in DetectabilityClass}
VALID_CATEGORIES = {c.value for c in ObservableCategory}


def _load():
    return json.loads(FIXTURE.read_text())


def test_fixture_has_30_cases_spanning_all_classes():
    data = _load()
    cases = data["cases"]
    assert len(cases) == 30
    classes = Counter(c["expected"]["detectability_class"] for c in cases)
    # all 5 classes represented, >=5 each (so the confusion matrix is populated)
    assert set(classes) == VALID_CLASSES
    assert min(classes.values()) >= 5


def test_every_case_is_structurally_valid():
    for c in _load()["cases"]:
        assert isinstance(c["id"], str) and c["id"]
        assert c["expected"]["detectability_class"] in VALID_CLASSES
        cve = c["cve"]
        assert cve["cve_id"] and cve["description"]
        lo = c["loop2_output"]
        assert set(lo["indicators"].keys()) <= VALID_CATEGORIES
        assert isinstance(lo["unanswered_questions"], list)
        gr = c["gate_result"]
        assert isinstance(gr["passed"], bool)
        assert isinstance(c["vuln_profile"], dict)


def test_case_ids_unique():
    ids = [c["id"] for c in _load()["cases"]]
    assert len(ids) == len(set(ids))
```

- [ ] **Step 2: Run, confirm fail**

Run: `.venv/bin/python -m pytest tests/evaluations/test_detectability_fixture.py -v`
Expected: FAIL — fixture file missing.

- [ ] **Step 3: Author the fixture**

Create `benchmarks/detectability_pilot_v1.json`. Top-level: `{"name": "detectability_pilot_v1", "description": "...", "cases": [ ... 30 ... ]}`.

Each case follows this EXEMPLAR shape exactly (this is case 1; produce 30 analogous):

```json
{
  "id": "case-01-log4shell",
  "cve": {
    "cve_id": "CVE-2021-44228",
    "title": "Apache Log4j2 JNDI RCE (Log4Shell)",
    "description": "Log4j2 JNDI lookup allows attacker-controlled LDAP/RMI URLs in logged strings to load and execute remote code."
  },
  "vuln_profile": {
    "vuln_class": "deserialization",
    "affected_component": "log4j-core JNDI lookup",
    "trigger_conditions": ["attacker-controlled string reaches a logging call"]
  },
  "loop2_output": {
    "indicators": {
      "network": [
        {"value": "outbound LDAP/RMI from a JVM process to an external host on 389/1099"},
        {"value": "subsequent HTTP fetch of a malicious Java class"}
      ],
      "process": [
        {"value": "java process spawning a shell (sh/bash/cmd) child"}
      ],
      "command_line": [
        {"value": "${jndi:ldap://...} pattern in request headers / logged fields"}
      ]
    },
    "unanswered_questions": []
  },
  "gate_result": {
    "passed": true,
    "filled_categories": ["network", "process", "command_line"],
    "empty_categories": ["file", "registry", "parent_child", "api_call"],
    "threshold": 3
  },
  "expected": {
    "detectability_class": "directly_detectable",
    "notes": "Strong, stable network egress + java->shell child + payload signature; high-fidelity in common telemetry."
  }
}
```

Author the 30 cases per this table (id = `case-NN-<slug>`). Fill `loop2_output.indicators` with REALISTIC public detection signals for each (model them on the CVE's real detection guidance), set `gate_result.passed`/`filled_categories`/`empty_categories` consistently with the indicators present (passed=true when ≥3 categories filled; for the `insufficient_information` cases set sparse indicators and `passed: false` with mostly empty categories), and set `expected.detectability_class` + a one-line `notes` rationale (this is the DRAFT label the owner adjudicates).

**directly_detectable (6)** — rich, stable host/network signal:
1. `case-01-log4shell` CVE-2021-44228 (deserialization) — LDAP egress + java→shell + `${jndi:` signature
2. `case-02-shellshock` CVE-2014-6271 (command injection) — httpd/apache→bash→curl child chain; `() {` in headers
3. `case-03-outlook-ntlm` CVE-2023-23397 (ntlm credential leak) — outlook.exe → SMB 445 egress to non-fileserver
4. `case-04-printnightmare-rce` CVE-2021-34527 (privilege/dll-load) — spoolsv.exe loads DLL from UNC share
5. `case-05-zerologon` CVE-2020-1472 (auth bypass) — burst of Netlogon RPC with zeroed challenge; 4742/anomalous RPC
6. `case-06-eternalblue` CVE-2017-0144 (memory corruption) — SMBv1 exploit traffic + svchost anomaly

**indirectly_detectable (6)** — signal exists but secondary/noisier (often the post-exploit artifact, not the exploit):
7. `case-07-proxylogon` CVE-2021-26855 (ssrf) — webshell file write under inetpub + w3wp child; exploit itself quiet
8. `case-08-citrix-adc` CVE-2019-19781 (path traversal) — perl template write + nobody-user process
9. `case-09-fortios-traversal` CVE-2018-13379 (path traversal) — sslvpn creds-file read; network + file
10. `case-10-f5-icontrol` CVE-2022-1388 (auth bypass) — bash spawned by the mgmt process; command_line
11. `case-11-vcenter-upload` CVE-2021-21972 (file upload) — uploaded JSP/webshell write + tomcat child
12. `case-12-bluekeep` CVE-2019-0708 (memory corruption) — RDP pre-auth anomaly; hard to distinguish from noise

**environment_dependent (6)** — detectable ONLY with telemetry/config many environments lack:
13. `case-13-curveball` CVE-2020-0601 (crypto spoofing) — needs CryptoAPI/Audit cert-validation logging (usually off)
14. `case-14-pwnkit` CVE-2021-4034 (privilege escalation) — pkexec execve; needs Linux auditd execve rules
15. `case-15-dirtycow` CVE-2016-5195 (race/privilege) — kernel race; needs auditd, rarely logged
16. `case-16-baron-samedit` CVE-2021-3156 (heap overflow/sudo) — needs sudo + auditd logging
17. `case-17-dirtypipe` CVE-2022-0847 (file overwrite) — needs file-integrity/auditd on the overwritten file
18. `case-18-sysmon-imageload` CVE-2021-1675 (dll load) — needs Sysmon EID 7 image-load (not default)

**control_only (6)** — no realistic runtime detection; mitigation/patch is the only answer:
19. `case-19-openssl-typeconf` CVE-2023-0286 (memory corruption) — X.400 type confusion; no host signal → mitigate
20. `case-20-openssl-punycode` CVE-2022-3602 (buffer overflow) — TLS cert punycode overflow; mitigation only
21. `case-21-openssl-sm2` CVE-2021-3711 (buffer overflow) — SM2 decrypt overflow; mitigation only
22. `case-22-heartbleed` CVE-2014-0160 (memory disclosure) — weak/absent host signal; patch + cert rotation
23. `case-23-libwebp` CVE-2023-4863 (heap overflow) — client-side image parse; mitigation/patch
24. `case-24-cisco-asa-read` CVE-2020-3452 (path read) — config/patch; minimal host telemetry

**insufficient_information (6)** — sparse/contradictory indicators; the classifier SHOULD decline:
25. `case-25-appliance-rce-vague` synthetic "unauthenticated RCE in appliance X, details withheld" — empty indicators, `passed:false`
26. `case-26-single-category` a CVE with only one indicator category filled, `passed:false`
27. `case-27-embargoed` reserved CVE, description "details embargoed", empty indicators
28. `case-28-contradictory` placeholder/contradictory indicators, gate empty
29. `case-29-http2-reset` CVE-2023-44487 (resource exhaustion / DoS) — availability-only, no host detection artifact, sparse
30. `case-30-no-public-detail` a CVE with no public detail and empty indicators, `passed:false`

For cases 25–30 set `vuln_profile` minimally (e.g. `{"vuln_class": "unknown", "affected_component": "unknown", "trigger_conditions": ["unknown"]}`) and indicators sparse/empty, `gate_result.passed=false`, `filled_categories` ⊊ (0–1 entries).

- [ ] **Step 4: Run the validation test**

Run: `.venv/bin/python -m pytest tests/evaluations/test_detectability_fixture.py -v`
Expected: 3 passed (30 cases, all classes ≥5, valid structure, unique ids). Fix the JSON until green.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/detectability_pilot_v1.json tests/evaluations/test_detectability_fixture.py
git commit -m "feat(w2c): 30-case detectability benchmark fixture (draft labels)"
```

---

## Task 4: Runner with `--dry-run`

**Files:**
- Create: `scripts/run_detectability_benchmark.py`
- Create: `tests/test_detectability_benchmark_dryrun.py`

- [ ] **Step 1: Write the failing dry-run test**

```python
# tests/test_detectability_benchmark_dryrun.py
"""The benchmark runner's --dry-run path validates fixtures with no LLM/DB."""
from __future__ import annotations

import importlib

runner = importlib.import_module("scripts.run_detectability_benchmark")


def test_load_fixture_returns_30_cases():
    cases = runner.load_fixture(runner.DEFAULT_FIXTURE)
    assert len(cases) == 30
    assert cases[0].expected_class in {
        "directly_detectable", "indirectly_detectable", "environment_dependent",
        "control_only", "insufficient_information",
    }


def test_dry_run_reports_label_distribution_without_llm():
    # dry-run scores the EXPECTED labels against themselves (sanity) -> accuracy 1.0,
    # exercising the fixture-load + metrics wiring with zero LLM calls.
    report = runner.dry_run(runner.DEFAULT_FIXTURE)
    assert report["n"] == 30
    assert report["accuracy"] == 1.0  # expected vs expected
    assert set(report["confusion_matrix"]["classes"]) == {
        "directly_detectable", "indirectly_detectable", "environment_dependent",
        "control_only", "insufficient_information",
    }
```

(Ensure `scripts/__init__.py` exists so `import scripts.run_detectability_benchmark` works; if `scripts/` is not a package, the test can instead load the module by path with `importlib.util` — check whether other `tests/` import from `scripts.` and mirror that. If none do, make `scripts/run_detectability_benchmark.py` importable and add `scripts/__init__.py` only if that matches repo convention; otherwise use a path-based import in the test.)

- [ ] **Step 2: Run, confirm fail**

Run: `.venv/bin/python -m pytest tests/test_detectability_benchmark_dryrun.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement the runner**

```python
# scripts/run_detectability_benchmark.py
"""Benchmark the DetectabilityClassifier against a curated fixture.

--dry-run : validate the fixture + run the metrics path on the EXPECTED labels
            (self-check), no LLM, no DB. CI exercises this.
(no flag) : run the real classifier per case (LLM spend) and print metrics.
--no-store: run the classifier but skip persisting a prompt_evaluations row.

The scored (non-dry-run) path is Phase 3 of the W2c plan and is run manually
against the deployed environment after the fixture labels are owner-adjudicated.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fragchain.evaluations.detectability_metrics import CaseOutcome, compute_metrics

DEFAULT_FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks" / "detectability_pilot_v1.json"


@dataclass
class BenchCase:
    case_id: str
    cve_id: str
    vuln_profile: dict[str, Any]
    loop2_output: dict[str, Any]
    gate_result: dict[str, Any]
    expected_class: str


def load_fixture(path: Path) -> list[BenchCase]:
    data = json.loads(Path(path).read_text())
    out: list[BenchCase] = []
    for c in data["cases"]:
        out.append(BenchCase(
            case_id=c["id"],
            cve_id=c["cve"]["cve_id"],
            vuln_profile=c["vuln_profile"],
            loop2_output=c["loop2_output"],
            gate_result=c["gate_result"],
            expected_class=c["expected"]["detectability_class"],
        ))
    return out


def dry_run(path: Path) -> dict:
    cases = load_fixture(path)
    outcomes = [
        CaseOutcome(case_id=c.case_id, expected=c.expected_class,
                    predicted=c.expected_class, confidence=1.0)
        for c in cases
    ]
    return compute_metrics(outcomes)


async def _score_case(classifier, case: BenchCase) -> tuple[CaseOutcome, float, float]:
    from fragchain.assessments.loops.base import LoopContext

    ctx = LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id=case.cve_id,
        source_contents=[],
        prior_outputs={1: {"vuln_profile": case.vuln_profile}},
    )
    started = time.perf_counter()
    pr = await classifier.predict(
        ctx=ctx, loop2_output=case.loop2_output, gate_result=case.gate_result
    )
    latency_ms = (time.perf_counter() - started) * 1000.0
    outcome = CaseOutcome(
        case_id=case.case_id,
        expected=case.expected_class,
        predicted=pr.assessment.detectability_class.value,
        confidence=float(pr.assessment.confidence),
    )
    return outcome, float(pr.cost_usd), latency_ms


async def run_scored(path: Path, *, store: bool, evaluated_by: str) -> dict:
    from fragchain.db.session import get_sessionmaker
    from fragchain.assessments.detectability import DetectabilityClassifier
    from fragchain.prompts.store import PromptStore

    cases = load_fixture(path)
    sm = get_sessionmaker()
    outcomes: list[CaseOutcome] = []
    costs: list[float] = []
    latencies: list[float] = []
    async with sm() as session:
        classifier = DetectabilityClassifier(session, prompt_store=PromptStore(session))
        for case in cases:
            outcome, cost, latency = await _score_case(classifier, case)
            outcomes.append(outcome)
            costs.append(cost)
            latencies.append(latency)
        report = compute_metrics(outcomes)
        report["per_case"] = [
            {"case_id": o.case_id, "expected": o.expected, "predicted": o.predicted,
             "confidence": o.confidence, "correct": o.correct}
            for o in outcomes
        ]
        report["mean_cost_usd"] = round(sum(costs) / len(costs), 6) if costs else 0.0
        report["mean_latency_ms"] = int(sum(latencies) / len(latencies)) if latencies else 0
        if store:
            await _persist(session, report, evaluated_by)
            await session.commit()
    return report


async def _persist(session, report: dict, evaluated_by: str) -> None:
    from decimal import Decimal
    from fragchain.db.models import PromptEvaluation
    from fragchain.prompts.store import PromptStore

    selection = await PromptStore(session).get_active(
        task_type="detectability_classification", target_model="*", target_provider="*",
    )
    session.add(PromptEvaluation(
        prompt_template_id=selection.id,
        benchmark_set="detectability_pilot_v1",
        cost_per_run=Decimal(str(report.get("mean_cost_usd", 0))),
        avg_latency_ms=report.get("mean_latency_ms"),
        sample_outputs=report,
        evaluated_by=evaluated_by,
    ))


def _print_summary(report: dict) -> None:
    print(f"n={report['n']} accuracy={report['accuracy']} macro_f1={report['macro_f1']}")
    cm = report["confusion_matrix"]
    print("confusion (rows=expected, cols=predicted):")
    print("  " + " ".join(f"{c[:4]}" for c in cm["classes"]))
    for cls, row in zip(cm["classes"], cm["matrix"]):
        print(f"  {cls[:20]:20} " + " ".join(f"{v:4d}" for v in row))
    print(f"calibration: {report['calibration']}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-store", action="store_true")
    ap.add_argument("--evaluated-by", default="benchmark")
    args = ap.parse_args()

    if args.dry_run:
        report = dry_run(args.fixture)
        _print_summary(report)
        return
    report = asyncio.run(run_scored(args.fixture, store=not args.no_store, evaluated_by=args.evaluated_by))
    _print_summary(report)


if __name__ == "__main__":
    main()
```

Confirm `PromptEvaluation` is the correct ORM class name (grep `class PromptEvaluation` in `fragchain/db/models.py`) and that `get_sessionmaker` is the right import (grep how other scripts in `scripts/` get a session — e.g. `scripts/eval_chain.py` — and mirror exactly; adjust the import if it differs). The scored path is NOT exercised by tests (no LLM in CI) — only `load_fixture` + `dry_run` are.

- [ ] **Step 4: Run the dry-run test**

Run: `.venv/bin/python -m pytest tests/test_detectability_benchmark_dryrun.py -v`
Expected: 2 passed. `.venv/bin/ruff check scripts/run_detectability_benchmark.py` → clean.

Also smoke the CLI dry-run by hand: `.venv/bin/python -m scripts.run_detectability_benchmark --dry-run` (or `.venv/bin/python scripts/run_detectability_benchmark.py --dry-run`) → prints `n=30 accuracy=1.0 ...`. (No LLM.)

- [ ] **Step 5: Commit**

```bash
git add scripts/run_detectability_benchmark.py tests/test_detectability_benchmark_dryrun.py
git commit -m "feat(w2c): detectability benchmark runner with no-spend --dry-run"
```

---

## Task 5: Adjudication review doc

**Files:**
- Modify: `scripts/run_detectability_benchmark.py` (add an `--emit-review-doc` mode)
- Create (generated, then committed): `docs/superpowers/specs/detectability_pilot_labels.md`

- [ ] **Step 1: Add a review-doc emitter to the runner**

Add to `scripts/run_detectability_benchmark.py`:

```python
def emit_review_doc(path: Path) -> str:
    cases = load_fixture(path)
    lines = [
        "# Detectability Pilot — Draft Labels for Adjudication",
        "",
        "Review each proposed `detectability_class`. Corrections go into",
        "`benchmarks/detectability_pilot_v1.json` (`expected.detectability_class`) —",
        "that JSON is the source of truth; regenerate this doc with",
        "`python scripts/run_detectability_benchmark.py --emit-review-doc`.",
        "",
        "| Case | CVE | Filled categories | Proposed class | Rationale |",
        "|---|---|---|---|---|",
    ]
    data = json.loads(Path(path).read_text())
    for c in data["cases"]:
        filled = ", ".join(c["gate_result"].get("filled_categories") or []) or "(none)"
        notes = (c["expected"].get("notes") or "").replace("|", "\\|")
        lines.append(
            f"| {c['id']} | {c['cve']['cve_id']} | {filled} "
            f"| `{c['expected']['detectability_class']}` | {notes} |"
        )
    return "\n".join(lines) + "\n"
```

Wire it into `main()`:

```python
    ap.add_argument("--emit-review-doc", action="store_true")
    ...
    if args.emit_review_doc:
        out = Path(__file__).resolve().parents[1] / "docs" / "superpowers" / "specs" / "detectability_pilot_labels.md"
        out.write_text(emit_review_doc(args.fixture))
        print(f"wrote {out}")
        return
```

- [ ] **Step 2: Add a test for the emitter (no LLM)**

Append to `tests/test_detectability_benchmark_dryrun.py`:

```python
def test_emit_review_doc_lists_all_cases():
    doc = runner.emit_review_doc(runner.DEFAULT_FIXTURE)
    assert doc.count("\n| case-") == 30  # one table row per case
    assert "Proposed class" in doc
```

- [ ] **Step 3: Run the test + generate the doc**

Run: `.venv/bin/python -m pytest tests/test_detectability_benchmark_dryrun.py -v` → all pass.
Generate: `.venv/bin/python scripts/run_detectability_benchmark.py --emit-review-doc` → writes `docs/superpowers/specs/detectability_pilot_labels.md`.

- [ ] **Step 4: Commit**

```bash
git add scripts/run_detectability_benchmark.py tests/test_detectability_benchmark_dryrun.py docs/superpowers/specs/detectability_pilot_labels.md
git commit -m "feat(w2c): emit adjudication review doc for the pilot labels"
```

---

## Task 6: Full-suite gate

**Files:** none (verification)

- [ ] **Step 1: Run the W2c suites + the classifier regression**

Run: `.venv/bin/python -m pytest tests/evaluations tests/test_detectability_benchmark_dryrun.py tests/assessments/test_detectability_classifier.py -q`
Expected: all pass.

- [ ] **Step 2: Broader regression (the refactor touched detectability.py, used in the orchestrator)**

Run: `.venv/bin/python -m pytest tests/assessments -q`
Expected: no new failures vs the known baseline.

- [ ] **Step 3: Mechanical-truth guards (new paths referenced in docs)**

Run: `.venv/bin/python scripts/verify_doc_claims.py && .venv/bin/python -m pytest tests/test_dormancy_claims.py -q`
Expected: pass.

- [ ] **Step 4: Push**

```bash
git push -u origin claude/wave2c-detectability-benchmark
```

---

## Self-review notes (author)

- **Spec coverage:** A (`predict()`) → Task 1; B (metrics) → Task 2; C (fixture) → Task 3; D (runner+dry-run) → Task 4; E (adjudication doc) → Task 5; F (tests) → every task + Task 6. ✅
- **Phasing honored:** no task runs the real classifier — Tasks 1–6 are zero-LLM-spend. The scored run (`run_scored`) exists in code but is unit-untested and only invoked manually in Phase 3 after adjudication.
- **Type consistency:** `CaseOutcome(case_id, expected, predicted, confidence)`, `compute_metrics(...) -> dict` with keys `n/accuracy/macro_f1/per_class/confusion_matrix/calibration`, `PredictResult(assessment, model, cost_usd, prompt_template_id)`, `BenchCase(...expected_class)` used consistently across Tasks 1/2/4.
- **No silent caps:** the fixture is exactly 30 (pilot scope, stated); the validation test enforces ≥5 per class.
