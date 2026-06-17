from __future__ import annotations

from pathlib import Path

from scripts.seed_prompts import DEFAULTS, PROMPTS_DIR


def test_vuln_analysis_default_present():
    matching = [d for d in DEFAULTS if d["task_type"] == "vuln_analysis"]
    assert len(matching) == 1, "expected exactly one vuln_analysis default"
    entry = matching[0]
    assert entry["name"] == "vuln_analysis"
    assert entry["system_filename"].endswith(".system.txt")
    assert entry["user_filename"].endswith(".user.txt")


def test_vuln_analysis_prompt_files_exist_and_have_required_content():
    entry = next(d for d in DEFAULTS if d["task_type"] == "vuln_analysis")
    system_path: Path = PROMPTS_DIR / entry["system_filename"]
    user_path: Path = PROMPTS_DIR / entry["user_filename"]

    assert system_path.exists(), f"missing {system_path}"
    assert user_path.exists(), f"missing {user_path}"

    system_text = system_path.read_text().lower()
    user_text = user_path.read_text()

    # System prompt must describe the JSON schema the loop validates against.
    assert "vuln_profile" in system_text
    assert "detection_questions" in system_text
    # The 7 observable categories must be named so the model knows what to emit.
    for cat in (
        "process", "command_line", "file", "network",
        "registry", "parent_child", "api_call",
    ):
        assert cat in system_text, f"category {cat} not mentioned in system prompt"

    # User template must contain the placeholders Loop 1's user_template.format(...) passes.
    assert "{cve_id}" in user_text
    assert "{cvss}" in user_text
    assert "{sources}" in user_text
