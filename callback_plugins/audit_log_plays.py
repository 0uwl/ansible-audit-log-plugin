from __future__ import annotations

DOCUMENTATION = r"""
author: 0uwl
name: audit_log_plays
type: notification
short_description: community.general.log_plays with dated folders and the invoking user
description:
  - Same output as C(community.general.log_plays), but written to C(YYYY/MM/DD/<host>) under C(log_folder),
    with C(user=<name>) appended to every line.
  - The user is taken from C(SUDO_USER), C(USER) or C(LOGNAME), the same way C(audit_log) does.
requirements:
  - Enable in C(callback_enabled)
  - The C(community.general) collection
  - A writeable C(log_folder) for the user executing Ansible on the controller
options:
  log_folder:
    default: /var/log/ansible/hosts
    description: The folder where log files are created, in C(YYYY/MM/DD) subfolders.
    type: str
    env:
      - name: ANSIBLE_LOG_FOLDER
    ini:
      - section: callback_audit_log_plays
        key: log_folder
"""

import os
from datetime import datetime, timezone

from ansible.utils.path import makedirs_safe
from ansible_collections.community.general.plugins.callback.log_plays import (
    CallbackModule as LogPlays,
)


def _now():
    return datetime.now(timezone.utc)


class CallbackModule(LogPlays):
    """
    logs playbook results, per host, in log_folder/YYYY/MM/DD, tagged with the invoking user
    """

    CALLBACK_NAME = "audit_log_plays"
    CALLBACK_NEEDS_ENABLED = True

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super().set_options(task_keys=task_keys, var_options=var_options, direct=direct)
        self.base_folder = self.log_folder

    def v2_playbook_on_start(self, playbook):
        super().v2_playbook_on_start(playbook)
        # date fixed at playbook start, so a run crossing midnight stays in one folder
        self.log_folder = os.path.join(self.base_folder, _now().strftime("%Y/%m/%d"))
        makedirs_safe(self.log_folder)
        env = os.environ
        self.user = env.get("SUDO_USER") or env.get("USER") or env.get("LOGNAME") or "unknown"

    def _make_msg(self, *args):
        return super()._make_msg(*args).rstrip("\n") + f" - user={self.user}\n\n"
