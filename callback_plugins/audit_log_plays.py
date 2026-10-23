from __future__ import annotations

DOCUMENTATION = r"""
author: 0uwl
name: audit_log_plays
type: notification
short_description: community.general.log_plays with dated folders and the invoking user
description:
  - Same output as C(community.general.log_plays), but written to C(YYYY/MM/DD/<owner>/<host>) under C(log_folder),
    with C(user=<name>) appended to every line.
  - The user is taken from C(SUDO_USER), C(USER) or C(LOGNAME), the same way C(audit_log) does.
  - C(<owner>) is the account of the effective uid, so it always matches the owner of the folder and its files.
  - The C(YYYY/MM/DD) folders are created setgid and group-writable (2770), so several users can log into the same day.
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
"""

import os
import pwd
from datetime import datetime, timezone

from ansible.utils.path import makedirs_safe
from ansible_collections.community.general.plugins.callback.log_plays import (
    CallbackModule as LogPlays,
)


def _now():
    return datetime.now(timezone.utc)


def _makedirs_shared(base, *parts):
    # dated folders are shared by every user: make the ones we create setgid + group-writable,
    # explicitly, since mkdir's mode is cut by the umask and the first user of the day would lock out the rest
    # future: a second user hitting the instant between mkdir and chmod gets PermissionError; retry if it ever shows
    path = base
    for part in parts:
        path = os.path.join(path, part)
        try:
            os.mkdir(path)
        except FileExistsError:
            continue
        os.chmod(path, 0o2770)
    return path


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

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super().set_options(task_keys=task_keys, var_options=var_options, direct=direct)
        self.base_folder = self.log_folder

    def v2_playbook_on_start(self, playbook):
        super().v2_playbook_on_start(playbook)
        # date fixed at playbook start, so a run crossing midnight stays in one folder
        dated = _makedirs_shared(self.base_folder, *_now().strftime("%Y %m %d").split())
        self.log_folder = os.path.join(dated, _owner())
        makedirs_safe(self.log_folder)
        env = os.environ
        self.user = env.get("SUDO_USER") or env.get("USER") or env.get("LOGNAME") or "unknown"

    def _make_msg(self, *args):
        return super()._make_msg(*args).rstrip("\n") + f" - user={self.user}\n\n"
