from __future__ import annotations

DOCUMENTATION = r"""
author: 0uwl
name: audit_log
type: notification
short_description: One JSONL or syslog-style audit file per playbook run
description:
  - Records who ran which playbook, when, with what options, and per-host outcomes.
  - The user is taken from the environment, which the caller controls. C(uid), C(host_uid) and C(loginuid) come from the kernel.
    In a rootful container with no user namespace and no audit session they all read as root or unset,
    so pass C(USER), C(SUDO_USER) or C(SSH_CONNECTION) into the container.
requirements:
  - Enable in C(callback_enabled)
  - A writeable C(audit_dir) for the user executing Ansible on the controller
options:
  audit_dir:
    default: /audit/logs
    description: The folder where audit files are created, in C(YYYY/MM) subfolders (created setgid and sticky, mode 3770).
    type: str
    env:
      - name: ANSIBLE_AUDIT_DIR
    ini:
      - section: callback_audit_log
        key: audit_dir
  syslog_format:
    default: false
    description: Write syslog-style C(key=value) lines to a C(.log) file instead of JSONL.
    type: bool
    env:
      - name: ANSIBLE_AUDIT_SYSLOG_FORMAT
    ini:
      - section: callback_audit_log
        key: syslog_format
  syslog:
    default: false
    description:
      - Also send every record to syslog (ident C(ansible-audit)), where it is written as the syslog user, or on another
        host, out of reach of the user running Ansible. Failed (also ignored), unreachable and async-failed results are sent as C(err), the rest as C(info).
      - If O(syslog_server) cannot be reached at startup, a warning is shown and only the audit file is written.
    type: bool
    env:
      - name: ANSIBLE_AUDIT_SYSLOG
    ini:
      - section: callback_audit_log
        key: syslog
  syslog_server:
    default: /dev/log
    description:
      - Where O(syslog) sends to, as in C(community.general.syslog_json). A path is a local socket, anything else a host
        reached over UDP on O(syslog_port).
    type: str
    env:
      - name: SYSLOG_SERVER
    ini:
      - section: callback_audit_log
        key: syslog_server
  syslog_port:
    default: 514
    description: Port of O(syslog_server) when it is a host.
    type: int
    env:
      - name: SYSLOG_PORT
    ini:
      - section: callback_audit_log
        key: syslog_port
  syslog_facility:
    default: user
    description: Syslog facility to log as.
    type: str
    env:
      - name: SYSLOG_FACILITY
    ini:
      - section: callback_audit_log
        key: syslog_facility
"""

import json
import logging
import logging.handlers
import os
import re
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from ansible import context
from ansible.parsing.ajson import AnsibleJSONEncoder
from ansible.parsing.splitter import parse_kv
from ansible.plugins.callback import CallbackBase
from ansible.utils.path import makedirs_safe


def _now():
    return datetime.now(timezone.utc)


def _makedirs_shared(base, *parts):
    # dated folders are shared by every user: make the ones we create setgid + group-writable, and sticky so nobody
    # can delete another user's file; explicitly, since mkdir's mode is cut by the umask and the first user of the day would lock out the rest
    # future: a second user hitting the instant between mkdir and chmod gets PermissionError; retry if it ever shows
    path = base
    for part in parts:
        path = os.path.join(path, part)
        try:
            os.mkdir(path)
        except FileExistsError:
            continue
        os.chmod(path, 0o3770)
    return path


_SECRET_NAME = re.compile(r"pass|secret|token|key", re.IGNORECASE)
_SECRET_KV = re.compile(rf"""(\w*(?:{_SECRET_NAME.pattern})\w*)=('[^']*'|"[^"]*"|\S+)""", re.IGNORECASE)


def _scrub(v):
    if isinstance(v, dict):
        return {k: "***" if _SECRET_NAME.search(str(k)) else _scrub(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_scrub(x) for x in v]
    return v


def _syslog_handler(server, port, facility, ident):
    # same transport as community.general.syslog_json, plus local sockets: a path is a socket, anything else host:port over UDP
    address = server if server.startswith("/") else (server, port)
    handler = logging.handlers.SysLogHandler(address=address, facility=facility)
    if handler.unixsocket and handler.socket.fileno() == -1:
        # SysLogHandler swallows a failed connect and would retry on every record, printing a traceback each time
        raise OSError("socket not reachable")
    handler.ident = f"{ident}[{os.getpid()}]: "
    return handler


def _send(handler, level, msg):
    # handler errors (oversized message, unknown facility) print to stderr instead of failing the run
    handler.handle(logging.makeLogRecord({"msg": msg, "levelname": level}))


def _host_uid(uid):
    # translate uid through the user namespace; rootless containers map their root to the real user
    try:
        with open("/proc/self/uid_map") as f:
            for line in f:
                inside, outside, count = map(int, line.split())
                if inside <= uid < inside + count:
                    return outside + uid - inside
    except (OSError, ValueError):
        pass
    return None


def _loginuid():
    # audit login uid, set by PAM at login and not changeable by the user; 4294967295 means unset
    try:
        with open("/proc/self/loginuid") as f:
            uid = int(f.read())
    except (OSError, ValueError):
        return None
    return None if uid == 4294967295 else uid


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


_BARE = re.compile(r"[A-Za-z0-9._/:@+-]+")


def _fmt(v):
    # bare only when unambiguous, otherwise JSON, so every value parses back exactly
    if isinstance(v, str) and _BARE.fullmatch(v):
        try:
            json.loads(v)  # "null", "true", "42" would read back as non-strings
        except ValueError:
            return v
    return json.dumps(v, cls=AnsibleJSONEncoder, separators=(",", ":"))


class CallbackModule(CallbackBase):
    """
    writes one JSONL (or syslog-style) audit file per playbook run under audit_dir
    """

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "audit_log"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self):
        super().__init__()
        self.run_id = uuid.uuid4().hex[:6]
        self.fh = None
        self.started = None
        self.syslog_format = False
        self.syslog = None
        self.host = socket.gethostname()

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super().set_options(task_keys=task_keys, var_options=var_options, direct=direct)

        self.audit_dir = self.get_option("audit_dir")
        makedirs_safe(self.audit_dir)
        self.syslog_format = self.get_option("syslog_format")
        if self.get_option("syslog"):
            server = self.get_option("syslog_server")
            try:
                self.syslog = _syslog_handler(server, self.get_option("syslog_port"), self.get_option("syslog_facility"), "ansible-audit")
            except OSError as e:
                self._display.warning(f"audit_log: cannot reach syslog at {server}, writing the file only: {e}")

    # --- helpers -----------------------------------------------------
    def _write(self, event, **data):
        if not self.fh:
            return
        rec = {"ts": _now().isoformat(), "run_id": self.run_id, "event": event, **data}
        if self.syslog_format:
            fields = " ".join(f"{k}={_fmt(v)}" for k, v in data.items())
            line = f"{rec['ts']} {self.host} ansible-audit[{self.run_id}]: {event} {fields}"
            # the syslog receiver stamps its own time and host, and the ident carries the pid, not the run_id
            msg = f"[{self.run_id}] {event} {fields}"
        else:
            msg = line = json.dumps(rec, cls=AnsibleJSONEncoder)
        self.fh.write(line + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())
        if self.syslog:
            failed = data.get("status") in ("failed", "failed_ignored", "unreachable", "async_failed") or data.get("success") is False
            _send(self.syslog, "ERROR" if failed else "INFO", msg)

    def _who(self):
        env = os.environ
        uid = os.getuid()
        return {
            "user": env.get("SUDO_USER") or env.get("USER") or env.get("LOGNAME") or "unknown",
            "login_user": env.get("USER"),
            "sudo_user": env.get("SUDO_USER"),
            "ssh_connection": env.get("SSH_CONNECTION"),
            "container_host": socket.gethostname(),
            "uid": uid,
            "host_uid": _host_uid(uid),
            "loginuid": _loginuid(),
        }

    # --- playbook lifecycle -----------------------------------------
    def v2_playbook_on_start(self, playbook):
        self.started = _now()
        d = _makedirs_shared(self.audit_dir, self.started.strftime("%Y"), self.started.strftime("%m"))

        pb = os.path.basename(playbook._file_name)
        who = self._who()["user"]
        safe = lambda s: re.sub(r"[^A-Za-z0-9._-]", "_", s)
        fname = f"{self.started.strftime('%Y%m%dT%H%M%SZ')}_{safe(who)}_{safe(pb)}_{self.run_id}.{'log' if self.syslog_format else 'jsonl'}"
        self.fh = open(os.path.join(d, fname), "a", encoding="utf-8")  # noqa: SIM115 - held open for the run, closed in v2_playbook_on_stats

        args = context.CLIARGS
        extra = args.get("extra_vars") or ()
        # names of all extra vars; values only appear in argv, with secret-looking ones redacted
        extra_keys = sorted({k for e in extra for k in _extra_keys(e)})

        self._write(
            "playbook_start",
            playbook=playbook._file_name,
            **self._who(),
            argv=[_redact(a) for a in Path("/proc/self/cmdline").read_text().split("\0")[:-1]],
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

    def v2_runner_on_ok(self, result):
        self._result("ok", result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._result("failed_ignored" if ignore_errors else "failed", result)

    def v2_runner_on_skipped(self, result):
        self._result("skipped", result)

    def v2_runner_on_unreachable(self, result):
        self._result("unreachable", result)

    def v2_runner_on_async_failed(self, result):
        self._result("async_failed", result)

    def v2_playbook_on_stats(self, stats):
        recap = {h: stats.summarize(h) for h in sorted(stats.processed.keys())}
        dur = (_now() - self.started).total_seconds() if self.started else None
        failed = any(v["failures"] or v["unreachable"] for v in recap.values())
        self._write("playbook_end", duration_s=dur, success=not failed, recap=recap)
        if self.fh:
            self.fh.close()
            self.fh = None