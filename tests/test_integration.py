import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="needs ansible-playbook")

ROOT = Path(__file__).resolve().parent.parent
PLAYBOOKS = ROOT / "tests" / "playbooks"


def run(tmp_path, playbook, *args, ini=None, env_dir=True):
    cfg = tmp_path / "ansible.cfg"
    cfg.write_text(ini or "")
    env = {
        "PATH": shutil.os.environ["PATH"],
        "HOME": str(tmp_path),
        "ANSIBLE_CONFIG": str(cfg),
        "ANSIBLE_CALLBACK_PLUGINS": str(ROOT / "callback_plugins"),
        "ANSIBLE_CALLBACKS_ENABLED": "audit_log",
        "ANSIBLE_LOCALHOST_WARNING": "false",
    }
    if env_dir:
        env["ANSIBLE_AUDIT_DIR"] = str(tmp_path / "audit")
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(PLAYBOOKS / playbook), *args],
        env=env, cwd=tmp_path, capture_output=True, text=True,
    )


def audit_file(tmp_path):
    (f,) = (tmp_path / "audit").rglob("*.jsonl")
    return f


def records(tmp_path):
    return [json.loads(line) for line in audit_file(tmp_path).read_text().splitlines()]


def test_smoke_run(tmp_path):
    p = run(tmp_path, "smoke.yml")
    assert p.returncode == 0, p.stdout + p.stderr

    f = audit_file(tmp_path)
    assert re.fullmatch(r"\d{8}T\d{6}Z_[^_].*_smoke\.yml_[0-9a-f]{6}\.jsonl", f.name)
    assert re.fullmatch(r"\d{4}/\d{2}", str(f.parent.relative_to(tmp_path / "audit")))

    recs = records(tmp_path)
    assert [r["event"] for r in recs] == (
        ["playbook_start", "play_start"] + ["task_start", "task_result"] * 4 + ["playbook_end"]
    )
    assert len({r["run_id"] for r in recs}) == 1

    results = [r for r in recs if r["event"] == "task_result"]
    assert [(r["task"], r["status"], r["changed"]) for r in results] == [
        ("ping", "ok", False),
        ("change", "ok", True),
        ("tolerated failure", "failed_ignored", True),
        ("skipped", "skipped", False),
    ]
    assert results[2]["rc"] == 1 and results[0]["host"] == "localhost"

    end = recs[-1]
    assert end["event"] == "playbook_end" and end["success"] is True
    assert end["recap"]["localhost"]["ok"] == 3 and end["recap"]["localhost"]["skipped"] == 1 and end["duration_s"] >= 0


def test_options_and_redaction(tmp_path):
    p = run(tmp_path, "smoke.yml", "-e", "env=prod", "-e", "db_password=s3cret", "--tags", "t", "--check")
    assert p.returncode == 0, p.stdout + p.stderr

    start = records(tmp_path)[0]
    assert start["extra_var_keys"] == ["db_password", "env"]
    assert start["tags"] == ["t"] and start["check_mode"] is True
    assert start["inventory"] == ["localhost,"]
    assert "db_password=***" in start["argv"]
    assert "s3cret" not in audit_file(tmp_path).read_text()


def test_failing_run(tmp_path):
    assert run(tmp_path, "fail.yml").returncode == 2
    recs = records(tmp_path)
    assert [r["status"] for r in recs if r["event"] == "task_result"] == ["failed"]
    assert recs[-1]["success"] is False


def test_ini_audit_dir(tmp_path):
    ini = f"[callback_audit_log]\naudit_dir = {tmp_path / 'audit'}\n"
    p = run(tmp_path, "smoke.yml", ini=ini, env_dir=False)
    assert p.returncode == 0, p.stdout + p.stderr
    assert records(tmp_path)[0]["event"] == "playbook_start"
