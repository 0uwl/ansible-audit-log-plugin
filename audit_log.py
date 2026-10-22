# /opt/ansible-audit/callback_plugins/audit_log.py
from __future__ import annotations

DOCUMENTATION = """
    name: audit_log
    type: notification
    short_description: One JSONL audit file per playbook run
    description: Records who ran which playbook, when, with what options, and per-host outcomes.
"""

import json
import os
import re
import socket
import uuid
from datetime import datetime, timezone

import yaml

from ansible import context
from ansible.parsing.splitter import parse_kv
from ansible.plugins.callback import CallbackBase


def _now():
    return datetime.now(timezone.utc)


# ponytail: name-based denylist; secrets under innocuous key names are not caught
_SECRET_NAME = re.compile(r"pass|secret|token|key", re.I)
_SECRET_KV = re.compile(rf"""(\w*(?:{_SECRET_NAME.pattern})\w*)=('[^']*'|"[^"]*"|\S+)""", re.I)


def _scrub(v):
    if isinstance(v, dict):
        return {k: "***" if _SECRET_NAME.search(str(k)) else _scrub(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_scrub(x) for x in v]
    return v


def _extra_keys(e):
    if e.lstrip().startswith(("{", "[")):
        try:
            data = yaml.safe_load(e)
        except yaml.YAMLError:
            return []
        return [str(k) for k in data] if isinstance(data, dict) else []
    return [k for k in parse_kv(e) if k != "_raw_params"]


def _redact(arg):
    prefix, body = ("--extra-vars=", arg[13:]) if arg.startswith("--extra-vars=") else ("", arg)
    if body.lstrip().startswith(("{", "[")):
        # JSON/YAML extra vars (YAML is a superset of JSON); re-emitted as compact JSON
        try:
            return prefix + json.dumps(_scrub(yaml.safe_load(body)), default=str)
        except yaml.YAMLError:
            pass
    return _SECRET_KV.sub(r"\1=***", arg)


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "audit_log"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self):
        super().__init__()
        self.run_id = uuid.uuid4().hex[:6]
        self.fh = None
        self.started = None

    # --- helpers -----------------------------------------------------
    def _write(self, event, **data):
        if not self.fh:
            return
        rec = {"ts": _now().isoformat(), "run_id": self.run_id, "event": event, **data}
        self.fh.write(json.dumps(rec, default=str) + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())

    def _who(self):
        env = os.environ
        return {
            "user": env.get("SUDO_USER") or env.get("USER") or env.get("LOGNAME") or "unknown",
            "login_user": env.get("USER"),
            "sudo_user": env.get("SUDO_USER"),
            "ssh_connection": env.get("SSH_CONNECTION"),
            "container_host": socket.gethostname(),
        }

    # --- playbook lifecycle -----------------------------------------
    def v2_playbook_on_start(self, playbook):
        self.started = _now()
        base = os.environ.get("ANSIBLE_AUDIT_DIR", "/audit/logs")
        d = os.path.join(base, self.started.strftime("%Y"), self.started.strftime("%m"))
        os.makedirs(d, exist_ok=True)

        pb = os.path.basename(playbook._file_name)
        who = self._who()["user"]
        safe = lambda s: re.sub(r"[^A-Za-z0-9._-]", "_", s)
        fname = f"{self.started.strftime('%Y%m%dT%H%M%SZ')}_{safe(who)}_{safe(pb)}_{self.run_id}.jsonl"
        self.fh = open(os.path.join(d, fname), "a", encoding="utf-8")

        args = context.CLIARGS
        extra = args.get("extra_vars") or ()
        # names of all extra vars; values only appear in argv, with secret-looking ones redacted
        # ponytail: @file vars yield no keys (file not read)
        extra_keys = sorted({k for e in extra for k in _extra_keys(e)})

        self._write(
            "playbook_start",
            playbook=playbook._file_name,
            **self._who(),
            argv=[_redact(a) for a in open("/proc/self/cmdline").read().split("\0")[:-1]],
            inventory=list(args.get("inventory") or []),
            limit=args.get("subset"),
            tags=list(args.get("tags") or []),
            skip_tags=list(args.get("skip_tags") or []),
            check_mode=bool(args.get("check")),
            diff_mode=bool(args.get("diff")),
            extra_var_keys=extra_keys,
        )

    def v2_playbook_on_play_start(self, play):
        self._write("play_start", play=play.get_name())

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._write("task_start", task=task.get_name(), action=task.action)

    # --- results (metadata only, no result bodies) ---------------------
    def _result(self, status, result):
        r = result._result
        self._write(
            "task_result",
            status=status,
            host=result._host.get_name(),
            task=result._task.get_name(),
            action=result._task.action,
            changed=bool(r.get("changed")),
            rc=r.get("rc"),
        )

    def v2_runner_on_ok(self, result, **kw):          self._result("ok", result)
    def v2_runner_on_failed(self, result, ignore_errors=False, **kw):
        self._result("failed_ignored" if ignore_errors else "failed", result)
    def v2_runner_on_skipped(self, result, **kw):     self._result("skipped", result)
    def v2_runner_on_unreachable(self, result, **kw): self._result("unreachable", result)

    def v2_playbook_on_stats(self, stats):
        recap = {h: stats.summarize(h) for h in sorted(stats.processed.keys())}
        dur = (_now() - self.started).total_seconds() if self.started else None
        failed = any(v["failures"] or v["unreachable"] for v in recap.values())
        self._write("playbook_end", duration_s=dur, success=not failed, recap=recap)
        if self.fh:
            self.fh.close()
            self.fh = None