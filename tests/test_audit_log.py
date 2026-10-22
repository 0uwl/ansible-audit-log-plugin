import io
import json
import os
import re
import socket
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import audit_log

T0 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
ID_VARS = ("USER", "SUDO_USER", "LOGNAME", "SSH_CONNECTION")


@pytest.fixture
def clock(monkeypatch):
    now = {"t": T0}
    monkeypatch.setattr(audit_log, "_now", lambda: now["t"])
    return now


@pytest.fixture
def cliargs(monkeypatch):
    args = {}
    monkeypatch.setattr(audit_log.context, "CLIARGS", args)
    return args


@pytest.fixture
def cb(tmp_path, monkeypatch, clock, cliargs):
    for v in ID_VARS:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("USER", "alice")
    c = audit_log.CallbackModule()
    c.audit_dir = str(tmp_path)
    yield c
    if c.fh:
        c.fh.close()


def records(tmp_path):
    (f,) = tmp_path.rglob("*.jsonl")
    return [json.loads(line) for line in f.read_text().splitlines()]


def playbook(path="/srv/site.yml"):
    return SimpleNamespace(_file_name=path)


def named(name, **kw):
    return MagicMock(get_name=MagicMock(return_value=name), **kw)


def result(host="web1", task="install", action="apt", **body):
    return SimpleNamespace(_host=named(host), _task=named(task, action=action), _result=body)


def stats(recap):
    return SimpleNamespace(processed=dict.fromkeys(recap), summarize=lambda h: recap[h])


def host_stats(failures=0, unreachable=0):
    return {"ok": 1, "changed": 0, "failures": failures, "unreachable": unreachable, "skipped": 0}


# --- _who --------------------------------------------------------------

def test_sudo_user_wins_over_user(cb, monkeypatch):
    monkeypatch.setenv("SUDO_USER", "bob")
    who = cb._who()
    assert (who["user"], who["login_user"], who["sudo_user"]) == ("bob", "alice", "bob")


@pytest.mark.parametrize("env, expected", [
    ({"USER": "alice", "LOGNAME": "carol"}, "alice"),
    ({"LOGNAME": "carol"}, "carol"),
    ({}, "unknown"),
])
def test_user_fallback_chain(cb, monkeypatch, env, expected):
    monkeypatch.delenv("USER")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert cb._who()["user"] == expected


def test_who_kernel_identity(cb):
    who = cb._who()
    assert who["uid"] == os.getuid()
    assert {"host_uid", "loginuid"} <= who.keys()


def fake_proc(monkeypatch, files):
    real_open = open

    def fake_open(path, *a, **kw):
        if path in files:
            if files[path] is None:
                raise FileNotFoundError(path)
            return io.StringIO(files[path])
        return real_open(path, *a, **kw)

    monkeypatch.setattr(audit_log, "open", fake_open, raising=False)


@pytest.mark.parametrize("uid_map, uid, expected", [
    ("         0          0 4294967295\n", 1000, 1000),
    ("         0       1000          1\n         1     100000      65536\n", 0, 1000),
    ("         0       1000          1\n         1     100000      65536\n", 5, 100004),
    ("         0       1000          1\n", 7, None),
    (None, 0, None),
    ("garbage\n", 0, None),
])
def test_host_uid(monkeypatch, uid_map, uid, expected):
    fake_proc(monkeypatch, {"/proc/self/uid_map": uid_map})
    assert audit_log._host_uid(uid) == expected


@pytest.mark.parametrize("content, expected", [("1000\n", 1000), ("4294967295\n", None), (None, None), ("x", None)])
def test_loginuid(monkeypatch, content, expected):
    fake_proc(monkeypatch, {"/proc/self/loginuid": content})
    assert audit_log._loginuid() == expected


def test_who_host_and_ssh(cb, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.1 5000 10.0.0.2 22")
    who = cb._who()
    assert who["container_host"] == socket.gethostname()
    assert who["ssh_connection"] == "10.0.0.1 5000 10.0.0.2 22"


# --- file creation -----------------------------------------------------

def test_file_path_layout(cb, tmp_path):
    cb.v2_playbook_on_start(playbook())
    expected = tmp_path / "2026" / "01" / f"20260102T030405Z_alice_site.yml_{cb.run_id}.jsonl"
    assert expected.is_file()


def test_unsafe_chars_sanitised(cb, tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "a b$c")
    cb.v2_playbook_on_start(playbook("/x/my play!.yml"))
    (f,) = tmp_path.rglob("*.jsonl")
    assert f.name == f"20260102T030405Z_a_b_c_my_play_.yml_{cb.run_id}.jsonl"


def test_set_options_creates_audit_dir(cb, tmp_path, monkeypatch):
    target = tmp_path / "new" / "logs"
    monkeypatch.setattr(audit_log.CallbackBase, "set_options", lambda *a, **kw: None)
    monkeypatch.setattr(cb, "get_option", lambda name: str(target))
    cb.set_options()
    assert cb.audit_dir == str(target) and target.is_dir()


# --- playbook_start record ---------------------------------------------

def test_playbook_start_maps_cliargs(cb, cliargs, tmp_path):
    cliargs.update(inventory=("hosts.ini",), subset="web*", tags=("a",), skip_tags=("b",),
                   check=True, diff=True)
    cb.v2_playbook_on_start(playbook())
    (rec,) = records(tmp_path)
    assert rec["event"] == "playbook_start"
    assert rec["playbook"] == "/srv/site.yml"
    assert rec["user"] == "alice"
    assert (rec["inventory"], rec["limit"], rec["tags"], rec["skip_tags"]) == (["hosts.ini"], "web*", ["a"], ["b"])
    assert rec["check_mode"] is rec["diff_mode"] is True


def test_playbook_start_empty_cliargs(cb, tmp_path):
    cb.v2_playbook_on_start(playbook())
    (rec,) = records(tmp_path)
    assert (rec["inventory"], rec["limit"], rec["tags"], rec["skip_tags"]) == ([], None, [], [])
    assert rec["check_mode"] is rec["diff_mode"] is False
    assert rec["extra_var_keys"] == []


@pytest.mark.skipif(not os.path.exists("/proc/self/cmdline"), reason="needs /proc")
def test_argv_recorded(cb, tmp_path):
    cb.v2_playbook_on_start(playbook())
    (rec,) = records(tmp_path)
    assert isinstance(rec["argv"], list) and rec["argv"]


@pytest.mark.parametrize("extra, keys", [
    (("a=1 b=2", "c=3", "a=9"), ["a", "b", "c"]),
    (("@vars.yml",), []),
    (("msg=x=y",), ["msg"]),
    (("msg='a b=c' d=1",), ["d", "msg"]),
    (('{"k": 1, "nested": {"inner": 2}}',), ["k", "nested"]),
    (("{db_pass: x}", "a=1"), ["a", "db_pass"]),
    (('["not", "a", "dict"]',), []),
    (('{"broken": ',), []),
])
def test_extra_var_keys(cb, cliargs, tmp_path, extra, keys):
    cliargs["extra_vars"] = extra
    cb.v2_playbook_on_start(playbook())
    assert records(tmp_path)[0]["extra_var_keys"] == keys


def test_argv_redacts_secret_extra_vars(cb, tmp_path, monkeypatch):
    cmdline = ["ansible-playbook", "-e", "password=s3cret env=prod", "--extra-vars=API_TOKEN=s3cret",
               "-e", "db_pass='s3cret s3cret' region=eu", "site.yml"]
    real_open = open

    def fake_open(path, *a, **kw):
        if path == "/proc/self/cmdline":
            return MagicMock(read=lambda: "\0".join(cmdline) + "\0")
        return real_open(path, *a, **kw)

    monkeypatch.setattr(audit_log, "open", fake_open, raising=False)
    cb.v2_playbook_on_start(playbook())
    (f,) = tmp_path.rglob("*.jsonl")
    assert "s3cret" not in f.read_text()
    assert records(tmp_path)[0]["argv"] == [
        "ansible-playbook", "-e", "password=*** env=prod", "--extra-vars=API_TOKEN=***",
        "-e", "db_pass=*** region=eu", "site.yml"]


@pytest.mark.parametrize("arg, expected", [
    ('{"password": "s3cret", "env": "prod"}', '{"password": "***", "env": "prod"}'),
    ('--extra-vars={"API_TOKEN": "s3cret"}', '--extra-vars={"API_TOKEN": "***"}'),
    ("{db_pass: s3cret, region: eu}", '{"db_pass": "***", "region": "eu"}'),
    ('{"app": {"creds": [{"ssh_key": "s3cret"}], "port": 8080}}',
     '{"app": {"creds": [{"ssh_key": "***"}], "port": 8080}}'),
    ('{"vault_password": {"nested": "s3cret"}}', '{"vault_password": "***"}'),
    ('{"password": "s3cret"', '{"password": "s3cret"'),  # invalid JSON/YAML: ansible would reject it first
    ("site.yml", "site.yml"),
])
def test_redact_json_extra_vars(arg, expected):
    assert audit_log._redact(arg) == expected


def test_every_record_has_envelope(cb, tmp_path):
    cb.v2_playbook_on_start(playbook())
    cb.v2_playbook_on_play_start(named("p"))
    for rec in records(tmp_path):
        assert rec["ts"] == T0.isoformat()
        assert re.fullmatch(r"[0-9a-f]{6}", rec["run_id"])
        assert rec["event"]


# --- lifecycle ---------------------------------------------------------

def test_play_and_task_start(cb, tmp_path):
    cb.v2_playbook_on_start(playbook())
    cb.v2_playbook_on_play_start(named("deploy"))
    cb.v2_playbook_on_task_start(named("install", action="apt"), is_conditional=False)
    _, play, task = records(tmp_path)
    assert play["event"] == "play_start" and play["play"] == "deploy"
    assert task == {**task, "event": "task_start", "task": "install", "action": "apt"}


def test_write_before_start_is_noop(cb, tmp_path):
    cb.v2_playbook_on_play_start(named("p"))
    cb.v2_runner_on_ok(result())
    assert not list(tmp_path.rglob("*.jsonl"))


# --- results -----------------------------------------------------------

@pytest.mark.parametrize("call, status", [
    (lambda c, r: c.v2_runner_on_ok(r), "ok"),
    (lambda c, r: c.v2_runner_on_failed(r), "failed"),
    (lambda c, r: c.v2_runner_on_failed(r, ignore_errors=True), "failed_ignored"),
    (lambda c, r: c.v2_runner_on_skipped(r), "skipped"),
    (lambda c, r: c.v2_runner_on_unreachable(r), "unreachable"),
    (lambda c, r: c.v2_runner_on_async_failed(r), "async_failed"),
])
def test_task_result_status(cb, tmp_path, call, status):
    cb.v2_playbook_on_start(playbook())
    call(cb, result(changed=1, rc=2))
    rec = records(tmp_path)[-1]
    assert rec["event"] == "task_result"
    assert (rec["status"], rec["host"], rec["task"], rec["action"]) == (status, "web1", "install", "apt")
    assert rec["changed"] is True and rec["rc"] == 2


def test_result_defaults(cb, tmp_path):
    cb.v2_playbook_on_start(playbook())
    cb.v2_runner_on_ok(result())
    rec = records(tmp_path)[-1]
    assert rec["changed"] is False and rec["rc"] is None


def test_result_body_not_logged(cb, tmp_path):
    cb.v2_playbook_on_start(playbook())
    cb.v2_runner_on_ok(result(stdout="token=hunter2", msg="hunter2"))
    (f,) = tmp_path.rglob("*.jsonl")
    assert "hunter2" not in f.read_text()


# --- stats -------------------------------------------------------------

def test_stats_success_and_duration(cb, clock, tmp_path):
    cb.v2_playbook_on_start(playbook())
    clock["t"] = T0 + timedelta(seconds=42)
    cb.v2_playbook_on_stats(stats({"web2": host_stats(), "web1": host_stats()}))
    rec = records(tmp_path)[-1]
    assert rec["event"] == "playbook_end"
    assert rec["success"] is True and rec["duration_s"] == 42
    assert list(rec["recap"]) == ["web1", "web2"]


@pytest.mark.parametrize("bad", [host_stats(failures=1), host_stats(unreachable=1)])
def test_stats_failure(cb, tmp_path, bad):
    cb.v2_playbook_on_start(playbook())
    cb.v2_playbook_on_stats(stats({"web1": host_stats(), "web2": bad}))
    assert records(tmp_path)[-1]["success"] is False


def test_stats_closes_file(cb, tmp_path):
    cb.v2_playbook_on_start(playbook())
    fh = cb.fh
    cb.v2_playbook_on_stats(stats({}))
    assert fh.closed and cb.fh is None
    cb.v2_runner_on_ok(result())
    assert records(tmp_path)[-1]["event"] == "playbook_end"


def test_stats_without_start(cb):
    cb.v2_playbook_on_stats(stats({"web1": host_stats()}))  # must not raise
    assert cb.fh is None


# --- full run ----------------------------------------------------------

def test_full_run_event_sequence(cb, tmp_path):
    cb.v2_playbook_on_start(playbook())
    cb.v2_playbook_on_play_start(named("p"))
    cb.v2_playbook_on_task_start(named("t", action="ping"), is_conditional=False)
    cb.v2_runner_on_ok(result())
    cb.v2_playbook_on_stats(stats({"web1": host_stats()}))
    recs = records(tmp_path)
    assert [r["event"] for r in recs] == ["playbook_start", "play_start", "task_start", "task_result", "playbook_end"]
    assert len({r["run_id"] for r in recs}) == 1
