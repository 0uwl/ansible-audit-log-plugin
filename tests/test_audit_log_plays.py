import os
import pwd
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import audit_log_plays
import pytest

T0 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
OWNER = audit_log_plays._owner()


@pytest.fixture
def clock(monkeypatch):
    now = {"t": T0}
    monkeypatch.setattr(audit_log_plays, "_now", lambda: now["t"])
    return now


@pytest.fixture
def cb(tmp_path, monkeypatch, clock):
    for v in ("USER", "SUDO_USER", "LOGNAME"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("USER", "alice")
    c = audit_log_plays.CallbackModule()
    c.log_folder = c.base_folder = str(tmp_path)
    return c


def result(host="web1"):
    named = lambda n, **kw: MagicMock(get_name=MagicMock(return_value=n), **kw)
    task = MagicMock(action="apt")
    task.name = "install"
    return SimpleNamespace(_host=named(host), _task=task, _result={"changed": False})


def test_dated_folder_per_host(cb, tmp_path):
    cb.v2_playbook_on_start(SimpleNamespace(_file_name="/srv/site.yml"))
    cb.v2_runner_on_ok(result())
    line = (tmp_path / "2026" / "01" / "02" / OWNER / "web1").read_text()
    assert " - /srv/site.yml - install - apt - OK - " in line
    assert line.endswith(" - user=alice\n\n")


def test_sudo_user_wins(cb, tmp_path, monkeypatch):
    monkeypatch.setenv("SUDO_USER", "bob")
    cb.v2_playbook_on_start(SimpleNamespace(_file_name="site.yml"))
    cb.v2_runner_on_ok(result())
    assert (tmp_path / "2026" / "01" / "02" / OWNER / "web1").read_text().endswith(" - user=bob\n\n")


def test_next_day_new_folder(cb, clock, tmp_path):
    cb.v2_playbook_on_start(SimpleNamespace(_file_name="site.yml"))
    clock["t"] = T0.replace(day=3)
    cb.v2_playbook_on_start(SimpleNamespace(_file_name="site.yml"))
    cb.v2_runner_on_ok(result())
    assert (tmp_path / "2026" / "01" / "03" / OWNER / "web1").is_file()
    assert cb.base_folder == str(tmp_path)


def test_owner_matches_file_owner(cb, tmp_path):
    cb.v2_playbook_on_start(SimpleNamespace(_file_name="site.yml"))
    cb.v2_runner_on_ok(result())
    (f,) = tmp_path.rglob("web1")
    assert f.parent.name == pwd.getpwuid(f.stat().st_uid).pw_name


def test_owner_falls_back_to_uid(monkeypatch):
    monkeypatch.setattr(audit_log_plays.pwd, "getpwuid", MagicMock(side_effect=KeyError))
    assert audit_log_plays._owner() == str(os.geteuid())


def test_dated_dirs_group_writable(cb, tmp_path):
    cb.v2_playbook_on_start(SimpleNamespace(_file_name="site.yml"))
    for d in ("2026", "2026/01", "2026/01/02"):
        assert (tmp_path / d).stat().st_mode & 0o7777 == 0o2770
    assert tmp_path.stat().st_mode & 0o7777 != 0o2770  # existing base folder left alone
