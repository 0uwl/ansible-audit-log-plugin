# ansible-audit-log-plugin

This repository contains two Callback Plugins for Ansible for generating proper audit logs for playbook runs. The plugins are intended for users who are not using AWX/AAP but still want to trace who runs what in a structured format.

`audit_log` is an Ansible callback plugin that writes one JSONL audit file per `ansible-playbook` run. It records who ran which playbook, when, with what options, and the outcome per host. Task output is not recorded; use the `audit_log_plays` plugin for that

`audit_log_plays` - A plugin which extends the existing community plugin [log_plays](https://docs.ansible.com/projects/ansible/latest/collections/community/general/log_plays_callback.html). It adds the invoking user's name
to every `log_plays` line and puts log files in a date-structured format `<audit_dir>/YYYY/MM/DD/<uid>/<host>.log`.

## Install

The plugins are a single files found in `callback_plugins/`. Put them where Ansible looks for callback plugins, using any one of:

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
| `syslog` | `false` | `ANSIBLE_AUDIT_SYSLOG` | `[callback_audit_log] syslog` |
| `syslog_server` | `/dev/log` | `SYSLOG_SERVER` | `[callback_audit_log] syslog_server` |
| `syslog_port` | `514` | `SYSLOG_PORT` | `[callback_audit_log] syslog_port` |
| `syslog_facility` | `user` | `SYSLOG_FACILITY` | `[callback_audit_log] syslog_facility` |

The directory is created at startup if missing, and the user running Ansible must be able to write to it. Files go in `YYYY/MM` subfolders. The `syslog*` options are described in [Tamper-proof archive](#tamper-proof-archive).

### Several users on one controller

The `YYYY/MM` folders are shared by everyone who runs playbooks, so the plugin creates them setgid, group-writable and sticky (mode `3770`) and does not leave it to the first user's umask. Give the users a common group and set up the base folder once:

```sh
groupadd ansible-log
usermod -aG ansible-log alice        # each user who runs playbooks, plus the log shipper
install -d -g ansible-log -m 3770 /audit/logs
```

New folders then inherit the group, and every member can add files to them. The sticky bit means only a file's owner can delete or rename it, so users can't remove each other's logs. Folders that already exist are left as they are.

## Use

Run playbooks as usual:

```sh
ANSIBLE_AUDIT_DIR=./audit ansible-playbook -i hosts site.yml -e env=prod
```

Each run produces a log file. `audit_log` creates `<audit_dir>/YYYY/MM/<UTC start>_<user>_<playbook>_<run_id>.jsonl`, for example `2026/10/20261022T193056Z_stvl_smoke.yml_1602b9.jsonl`. `audit_log_plays` creates `<audit_dir>/YYYY/MM/ <uid>/<hostname>.log`. Characters outside `A-Za-z0-9._-` in the user and playbook name become `_`.

### Audit log format

One JSON object per line. Every line has `ts` (UTC ISO 8601), `run_id` (shared by the whole run) and `event`.

| `event` | Extra fields |
| --- | --- |
| `playbook_start` | `playbook`, `user`, `login_user`, `sudo_user`, `ssh_connection`, `container_host`, `uid`, `host_uid`, `loginuid`, `argv`, `inventory`, `limit`, `tags`, `skip_tags`, `check_mode`, `diff_mode`, `extra_var_keys` |
| `play_start` | `play` |
| `task_start` | `task`, `action` |
| `task_result` | `status` (`ok`, `failed`, `failed_ignored`, `skipped`, `unreachable`, `async_failed`), `host`, `task`, `action`, `changed`, `rc` |
| `playbook_end` | `duration_s`, `success`, `recap` (per-host counts) |

#### Syslog format

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

Apart from the `syslog` option (see [Tamper-proof archive](#tamper-proof-archive)), the plugin does not ship logs itself. Point a file-tailing agent at `audit_dir`; a slow or unreachable SIEM then never affects a playbook run. The examples assume the default `/audit/logs`. The agent's user needs read access to it. Each run is a new file, and both tools below pick up new `YYYY/MM` directories on their own.

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

## audit_log_plays

`callback_plugins/audit_log_plays.py` extends the community `log_plays` plugin, so task output is logged per host as before, with two changes:

- files go in `<log_folder>/YYYY/MM/DD/<owner>/<host>.log`, dated by the UTC playbook start time
- each line ends with ` - user=<name>`, resolved the same way as `audit_log` (`SUDO_USER`, then `USER`, then `LOGNAME`)

`<owner>` is the account of the effective uid, taken from the kernel rather than the environment, so it always matches the owner of the folder and its files. `user=` is the user named in the environment. Under `sudo` the folder is `root/` and the line says `user=alice`. If the two disagree without sudo, someone changed `USER`.

In a rootless container (such as podman), Ansible runs as uid 0 inside, but the files are owned by your real user on the host. The plugin translates the uid through `/proc/self/uid_map`, so the folder is the host uid number, for example `1000/`. The container's `/etc/passwd` doesn't know host accounts, so the number is used rather than a name. On the host, `getent passwd 1000` gives the name. With `--userns=keep-id` the uid is the same inside and out, so the folder gets the name. In a rootful container the folder is `root/`, because the files really are owned by root.

For the shared group to work in a rootless container, the group has to be visible inside it: `podman run --group-add keep-groups`.

The `YYYY/MM/DD` folders are created setgid and sticky with mode `3770`, the same as `audit_log`'s, so set up `log_folder` with a shared group the same way (see [Several users on one controller](#several-users-on-one-controller)).

It needs the `community.general` collection. Enable it with `callbacks_enabled = audit_log_plays`. The folder is set with `ANSIBLE_LOG_FOLDER` or `[callback_audit_log_plays] log_folder`, default `/var/log/ansible/hosts`.

It has the same `syslog`, `syslog_server`, `syslog_port` and `syslog_facility` options as `audit_log`, in the `[callback_audit_log_plays]` ini section. The switch is `ANSIBLE_AUDIT_PLAYS_SYSLOG`. Each line is sent as `host=<host> <line>`, since the host is otherwise only in the file name.

## Tamper-proof archive

The user running Ansible owns the files it writes, so they can edit or delete them. With `syslog` enabled, both plugins also send every record to syslog as it is written. The syslog daemon then stores it as its own user, or on another machine, where the Ansible user can't change it. The files stay as they are and serve as the live logs.

The transport and option names match `community.general.syslog_json`, and so do the `SYSLOG_SERVER`, `SYSLOG_PORT` and `SYSLOG_FACILITY` variables, which are shared with that plugin. `syslog_server` is either a socket path, default `/dev/log`, or a host reached over UDP on `syslog_port`. The ident is `ansible-audit` or `ansible-audit-plays`. Failed (including ignored), unreachable and async-failed results are sent at priority `err`, everything else at `info`. In JSONL mode `audit_log` sends the JSON record. With `syslog_format` it sends `[<run_id>] <event> key=value ...` without the timestamp and host, which the syslog daemon adds itself.

```sh
ANSIBLE_AUDIT_SYSLOG=1 ANSIBLE_AUDIT_PLAYS_SYSLOG=1 ansible-playbook site.yml
journalctl -t ansible-audit -t ansible-audit-plays
```

To keep the archive in files, add an rsyslog rule, for example `/etc/rsyslog.d/30-ansible-audit.conf`:

```
if $programname == 'ansible-audit' then {
    action(type="omfile" file="/var/log/ansible-audit/audit.log"
           fileOwner="syslog" fileGroup="adm" fileCreateMode="0640" dirCreateMode="0750")
    stop
}
if $programname == 'ansible-audit-plays' then {
    action(type="omfile" file="/var/log/ansible-audit/plays.log"
           fileOwner="syslog" fileGroup="adm" fileCreateMode="0640" dirCreateMode="0750")
    stop
}
```

`syslog:adm` is the Debian/Ubuntu convention. On RHEL, rsyslog runs as root. Rotate the files with logrotate as usual.

Message size:

- rsyslog cuts messages at 8 KB by default. A long `playbook_start` argv or a large task result goes past that, so raise the limit with `global(maxMessageSize="64k")` at the top of `/etc/rsyslog.conf`, before any input module is loaded.
- Over UDP a message can't be larger than about 64 KB. Anything bigger, which in practice means a big task result from `audit_log_plays`, is not sent and a logging error is printed. The file always has the complete line.

The plays archive holds full task results, so it carries the same secret exposure as the live files. Keep its read access tight.

**Containers.** In rootless podman, mount the host's socket with `-v /dev/log:/dev/log`, or point `syslog_server` at a remote host. If `syslog_server` is a socket that can't be reached at startup, the plugin shows a warning and writes only the file.

**Limits.** This makes the logs tamper-evident, not tamper-proof:

- Anyone who can write to `/dev/log` can add fake lines with a matching ident, but nobody can change or delete what's already archived.
- A user can still turn the callback off. That run then has no archive lines, and the gap is visible.
- UDP to a remote host is unauthenticated and can lose packets. For stronger guarantees, have the local rsyslog forward over TCP or RELP rather than sending UDP straight from the plugin.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
