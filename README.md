# ansible-audit-log-plugin

An Ansible callback plugin that writes one JSONL audit file per `ansible-playbook` run. It records who ran which playbook, when, with what options, and the outcome per host. Task output is not recorded; use the [log_plays](https://docs.ansible.com/projects/ansible/latest/collections/community/general/log_plays_callback.html) community plugin for that.

## Install

The plugin is a single file, `callback_plugins/audit_log.py`. Put it where Ansible looks for callback plugins, using any one of:

- a `callback_plugins/` directory next to the playbook
- a directory listed in `callback_plugins` in `ansible.cfg`, or in `ANSIBLE_CALLBACK_PLUGINS`
- `~/.ansible/plugins/callback/`

Requires Python 3.10+, `ansible-core`, and PyYAML (which ansible-core already installs).

Then enable it in `ansible.cfg`:

```ini
[defaults]
callbacks_enabled = audit_log
```

or with `ANSIBLE_CALLBACKS_ENABLED=audit_log`.

## Configure

| Option | Default | Env | ini |
| --- | --- | --- | --- |
| `audit_dir` | `/audit/logs` | `ANSIBLE_AUDIT_DIR` | `[callback_audit_log] audit_dir` |

The directory is created at startup if missing, and the user running Ansible must be able to write to it. Files go in `YYYY/MM` subfolders.

## Use

Run playbooks as usual:

```sh
ANSIBLE_AUDIT_DIR=./audit ansible-playbook -i hosts site.yml -e env=prod
```

Each run produces `<audit_dir>/YYYY/MM/<UTC start>_<user>_<playbook>_<run_id>.jsonl`, for example `2026/10/20261022T193056Z_stvl_smoke.yml_1602b9.jsonl`. Characters outside `A-Za-z0-9._-` in the user and playbook name become `_`.

### Format

One JSON object per line. Every line has `ts` (UTC ISO 8601), `run_id` (shared by the whole run) and `event`.

| `event` | Extra fields |
| --- | --- |
| `playbook_start` | `playbook`, `user`, `login_user`, `sudo_user`, `ssh_connection`, `container_host`, `uid`, `host_uid`, `loginuid`, `argv`, `inventory`, `limit`, `tags`, `skip_tags`, `check_mode`, `diff_mode`, `extra_var_keys` |
| `play_start` | `play` |
| `task_start` | `task`, `action` |
| `task_result` | `status` (`ok`, `failed`, `failed_ignored`, `skipped`, `unreachable`, `async_failed`), `host`, `task`, `action`, `changed`, `rc` |
| `playbook_end` | `duration_s`, `success`, `recap` (per-host counts) |

Query with `jq`, for example failed tasks across all runs:

```sh
jq -c 'select(.event == "task_result" and .status == "failed")' audit/*/*/*.jsonl
```

### Who ran it

`user` is `SUDO_USER`, else `USER`, else `LOGNAME`, else `unknown`. However, environment variables are set by the caller and can be spoofed. For that reason the log also records values from the kernel:

- `uid`: `os.getuid()`. An easy check, but is often 0 inside a container.
- `host_uid`: `uid` translated through `/proc/self/uid_map`. In rootless podman this recovers the real host user.
- `loginuid`: the audit login UID from `/proc/self/loginuid`, or `null` if unset.

In a rootful container with no user namespace, all three read as root or unset. Pass `USER`, `SUDO_USER` or `SSH_CONNECTION` into the container so `user` and `ssh_connection` are still meaningful.

### Secrets

- `argv` is the full command line, with secret-looking values redacted: any `key=value` or JSON/YAML key whose name contains `pass`, `secret`, `token` or `key` becomes `***`.
- Extra vars are recorded as names only (`extra_var_keys`).
- Task results record metadata only, never `stdout`, `msg` or other output.

Redaction is name-based. A secret passed under an innocuous name, such as `-e foo=hunter2`, still appears in `argv`.

### Durability

Each record is flushed and `fsync`ed as it is written, so a crashed run still leaves a log up to the failure, without a playbook_end line.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
