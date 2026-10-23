# ansible-audit-log-plugin

`audit_log` is an Ansible callback plugin that writes one JSONL audit file per `ansible-playbook` run. It records who ran which playbook, when, with what options, and the outcome per host. Task output is not recorded; use the [log_plays](https://docs.ansible.com/projects/ansible/latest/collections/community/general/log_plays_callback.html) community plugin for that. This plugin
is intended for users who are not using AWX/AAP but still want to trace who runs what in a structured format.

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
| `syslog_format` | `false` | `ANSIBLE_AUDIT_SYSLOG_FORMAT` | `[callback_audit_log] syslog_format` |

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

### Syslog format

With `syslog_format` enabled, the file ends in `.log` instead of `.jsonl` and each record is one line of the form `<ts> <container_host> ansible-audit[<run_id>]: <event> key=value ...`, with the same fields in the same order:

```
2026-10-22T19:30:58.910000+00:00 ctl01 ansible-audit[1602b9]: task_result status=failed host=web1 task="Install nginx" action=apt changed=false rc=100
```

Nothing is lost. A string is written bare only if it contains just `A-Za-z0-9._/:@+-` and would not read as another type. Every other value is compact JSON, so `sudo_user=null` means unset, `sudo_user="null"` is the literal string, and lists and the recap are JSON arrays and objects. The `jq` and shipping examples below assume the default JSONL format.

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

### Shipping logs

The plugin does not ship logs itself. Point a file-tailing agent at `audit_dir`; a slow or unreachable SIEM then never affects a playbook run. The examples assume the default `/audit/logs`. The agent's user needs read access to it. Each run is a new file, and both tools below pick up new `YYYY/MM` directories on their own.

Filebeat (`filebeat.yml`):

```yaml
filebeat.inputs:
  - type: filestream
    id: ansible-audit
    paths:
      - /audit/logs/*/*/*.jsonl
    parsers:
      - ndjson:
          target: ""
          add_error_key: true

output.logstash:
  hosts: ["logstash:5044"]
```

Vector (`vector.yaml`):

```yaml
sources:
  audit_files:
    type: file
    include:
      - /audit/logs/*/*/*.jsonl

transforms:
  audit_json:
    type: remap
    inputs: [audit_files]
    source: |
      . = parse_json!(.message)

sinks:
  out:
    type: elasticsearch
    inputs: [audit_json]
    endpoints: ["http://elasticsearch:9200"]
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
