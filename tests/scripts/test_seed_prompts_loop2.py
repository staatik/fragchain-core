from __future__ import annotations

from pathlib import Path

from scripts.seed_prompts import DEFAULTS, PROMPTS_DIR


def test_threat_intel_default_present():
    matching = [d for d in DEFAULTS if d["task_type"] == "threat_intel"]
    assert len(matching) == 1, "expected exactly one threat_intel default"
    entry = matching[0]
    assert entry["name"] == "threat_intel"
    assert entry["system_filename"].endswith(".system.txt")
    assert entry["user_filename"].endswith(".user.txt")


def test_threat_intel_prompt_files_exist_and_have_required_content():
    entry = next(d for d in DEFAULTS if d["task_type"] == "threat_intel")
    system_path: Path = PROMPTS_DIR / entry["system_filename"]
    user_path: Path = PROMPTS_DIR / entry["user_filename"]

    assert system_path.exists(), f"missing {system_path}"
    assert user_path.exists(), f"missing {user_path}"

    system_text = system_path.read_text().lower()
    user_text = user_path.read_text()

    # System prompt must describe the Loop 2 schema + grounding rule.
    assert "indicators" in system_text
    assert "behavioral" in system_text
    # All 7 observable categories must be enumerable from the prompt.
    for cat in (
        "process", "command_line", "file", "network",
        "registry", "parent_child", "api_call",
    ):
        assert cat in system_text, f"category {cat} not mentioned in system prompt"
    # Grounding rule
    assert "source_ref" in system_text

    # User template must contain the 3 placeholders Loop 2 will format() with.
    assert "{detection_questions}" in user_text
    assert "{rag_results}" in user_text
    assert "{pass_hint}" in user_text
