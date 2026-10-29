from __future__ import annotations

DOCUMENTATION = r"""
author: 0uwl
name: audit_log_plays
type: notification
short_description: community.general.log_plays with dated folders and the invoking user
description:
  - Same output as C(community.general.log_plays), but written to C(YYYY/MM/DD/<owner>/<host>.log) under C(log_folder),
    with C(user=<name>) appended to every line.
  - The user is taken from C(SUDO_USER), C(USER) or C(LOGNAME), the same way C(audit_log) does.
  - C(<owner>) is the account of the effective uid, so it always matches the owner of the folder and its files.
  - The C(YYYY/MM/DD) folders are created setgid, group-writable and sticky (3770), so several users can log into the same day
    but none can delete another's files.
requirements:
  - Enable in C(callback_enabled)
  - The C(community.general) collection
  - A writeable C(log_folder) for the user executing Ansible on the controller
options:
  log_folder:
    default: /var/log/ansible/hosts
    description: The folder where log files are created, in C(YYYY/MM/DD/<owner>) subfolders.
    type: str
    env:
      - name: ANSIBLE_LOG_FOLDER
    ini:
      - section: callback_audit_log_plays
        key: log_folder
  syslog:
    default: false
    description:
      - Also send every line, prefixed with C(host=<host>), to syslog (ident C(ansible-audit-plays)), where it is written as the
        syslog user, or on another host, out of reach of the user running Ansible. Failed, unreachable and async-failed results
        are sent as C(err), the rest as C(info).
      - If O(syslog_server) cannot be reached at startup, a warning is shown and only the log file is written.
    type: bool
    env:
      - name: ANSIBLE_AUDIT_PLAYS_SYSLOG
    ini:
      - section: callback_audit_log_plays
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
      - section: callback_audit_log_plays
        key: syslog_server
  syslog_port:
    default: 514
    description: Port of O(syslog_server) when it is a host.
    type: int
    env:
      - name: SYSLOG_PORT
    ini:
      - section: callback_audit_log_plays
        key: syslog_port
  syslog_facility:
    default: user
    description: Syslog facility to log as.
    type: str
    env:
      - name: SYSLOG_FACILITY
    ini:
      - section: callback_audit_log_plays
        key: syslog_facility
"""

import json
import logging
import logging.handlers
import os
import pwd
import time
from collections.abc import MutableMapping
from datetime import datetime, timezone

from ansible.module_utils.common.text.converters import to_bytes
from ansible.parsing.ajson import AnsibleJSONEncoder
from ansible.utils.path import makedirs_safe
from ansible_collections.community.general.plugins.callback.log_plays import (
    CallbackModule as LogPlays,
)

try:
    from ansible_collections.community.general.plugins.module_utils._secrets import (
        mask_secrets,
    )
except ImportError:
    # older community.general (e.g. 9.x, the newest on python 3.10) has no secret masking
    def mask_secrets(value):
        return value


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


def _owner():
    # name of the uid that will own the files, from the kernel rather than the environment
    uid = os.geteuid()
    host = _host_uid(uid)
    if host is not None and host != uid:
        # inside a user namespace: the container's passwd doesn't know the host account, and may give
        # the host uid a different name (uid 1000 is "ubuntu" in ubuntu images), so use the number
        return str(host)
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


class CallbackModule(LogPlays):
    """
    logs playbook results, per host, in log_folder/YYYY/MM/DD/<owner>, tagged with the invoking user
    """

    CALLBACK_NAME = "audit_log_plays"
    CALLBACK_NEEDS_ENABLED = True
    syslog = None

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super().set_options(task_keys=task_keys, var_options=var_options, direct=direct)
        self.base_folder = self.log_folder
        if self.get_option("syslog"):
            server = self.get_option("syslog_server")
            try:
                self.syslog = _syslog_handler(server, self.get_option("syslog_port"), self.get_option("syslog_facility"), "ansible-audit-plays")
            except OSError as e:
                self._display.warning(f"audit_log_plays: cannot reach syslog at {server}, writing the file only: {e}")

    def v2_playbook_on_start(self, playbook):
        super().v2_playbook_on_start(playbook)
        # date fixed at playbook start, so a run crossing midnight stays in one folder
        dated = _makedirs_shared(self.base_folder, *_now().strftime("%Y %m %d").split())
        self.log_folder = os.path.join(dated, _owner())
        makedirs_safe(self.log_folder)
        env = os.environ
        self.user = env.get("SUDO_USER") or env.get("USER") or env.get("LOGNAME") or "unknown"

    def log(self, result, category):
        # copy of LogPlays.log (community.general 13.5.0), which has no hook for the file name; only the path differs
        data = result._result
        if isinstance(data, MutableMapping):
            if "_ansible_verbose_override" in data:
                # avoid logging extraneous data
                data = "omitted"
            else:
                data = data.copy()
                invocation = data.pop("invocation", None)
                data = json.dumps(data, cls=AnsibleJSONEncoder)
                if invocation is not None:
                    data = f"{json.dumps(invocation)} => {data} "

        host = result._host.get_name()
        path = os.path.join(self.log_folder, f"{host}.log")
        now = time.strftime(self.TIME_FORMAT, time.localtime())

        line = self._make_msg(now, self.playbook, result._task.name, result._task.action, category, data)
        with open(path, "ab") as fd:
            fd.write(to_bytes(line))
        if self.syslog:
            # the file name carries the host, the line doesn't
            level = "ERROR" if category in ("FAILED", "UNREACHABLE", "ASYNC_FAILED") else "INFO"
            _send(self.syslog, level, f"host={host} {line.rstrip()}")

    def _make_msg(self, now, playbook, task_name, task_action, category, data):
        # LogPlays._make_msg's line, built here since older community.general doesn't have it
        return f"{now} - user={self.user} - {playbook} - {mask_secrets(task_name)} - {task_action} - {category} - {data}\n\n"
