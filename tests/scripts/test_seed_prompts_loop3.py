from __future__ import annotations

from pathlib import Path

from scripts.seed_prompts import DEFAULTS, PROMPTS_DIR


def test_detection_engineering_default_present():
    matching = [d for d in DEFAULTS if d["task_type"] == "detection_engineering"]
    assert len(matching) == 1
    entry = matching[0]
    assert entry["name"] == "detection_engineering"
    assert entry["system_filename"].endswith(".system.txt")
    assert entry["user_filename"].endswith(".user.txt")


def test_detection_engineering_prompt_files_exist_and_have_required_content():
    entry = next(d for d in DEFAULTS if d["task_type"] == "detection_engineering")
    system_path: Path = PROMPTS_DIR / entry["system_filename"]
    user_path: Path = PROMPTS_DIR / entry["user_filename"]

    assert system_path.exists(), f"missing {system_path}"
    assert user_path.exists(), f"missing {user_path}"

    system_text = system_path.read_text().lower()
    user_text = user_path.read_text()

    # System prompt must constrain Sigma YAML output and ground in indicators.
    assert "sigma" in system_text
    assert "behavioral indicators" in system_text or "indicators" in system_text
    assert "yaml" in system_text  # output format constraint

    # User template MUST contain the real placeholders RuleGenerator passes.
    assert "{behavioral_indicators}" in user_text
    assert "{technique_id}" in user_text
    assert "{technique_name}" in user_text
    assert "{profile_name}" in user_text
    assert "{cve_id}" in user_text
