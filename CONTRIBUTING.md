# Contributing

## Setup

You need [uv](https://docs.astral.sh/uv/). Dependencies (`ansible-core`, `pytest`, `pyyaml`) are declared in the `dev` group in `pyproject.toml`; uv installs them into `.venv/` on first run.

## Running the tests

```sh
uv run pytest
```

Useful variations:

```sh
uv run pytest tests/test_audit_log.py          # unit tests only, ~1s
uv run pytest tests/test_integration.py        # real ansible-playbook runs, ~5s
uv run pytest -k redact -x                     # one topic, stop at first failure
```

## Test layout

- `tests/test_audit_log.py` — unit tests. They call the callback methods directly with mocked playbook, task, result and stats objects. The clock, `CLIARGS` and environment are patched by fixtures, so output is deterministic. Add a test here for any new field or branch.
- `tests/test_integration.py` — runs the real `ansible-playbook` against localhost with the plugin enabled, then reads the resulting JSONL. Each test runs in `tmp_path` with its own `HOME`, `ANSIBLE_CONFIG` and `ANSIBLE_AUDIT_DIR`, so user config cannot leak in. The module is skipped when `ansible-playbook` is not on `PATH`.
- `tests/playbooks/` — playbooks used by the integration tests. `smoke.yml` produces one task each of `ok`/changed, `failed_ignored` and `skipped`. `fail.yml` fails outright.

Unit tests prove the logic; integration tests prove Ansible loads the plugin and hands it real objects. A change to event fields or handlers should be covered by both.

## Trying a change by hand

```sh
ANSIBLE_CALLBACK_PLUGINS=callback_plugins \
ANSIBLE_CALLBACKS_ENABLED=audit_log \
ANSIBLE_AUDIT_DIR=/tmp/audit \
uv run ansible-playbook -i localhost, tests/playbooks/smoke.yml
```

## Conventions

- Follow the style of `community.general` callback plugins: options declared in `DOCUMENTATION` and read with `get_option`, one explicit method per `v2_*` handler, Ansible helpers (`makedirs_safe`, `AnsibleJSONEncoder`) over stdlib equivalents.
- Never write task result bodies or unredacted extra-var values to the log.
- `.gitignore` covers `__pycache__/` and `.venv/`; do not commit either.
- Commit messages use a conventional prefix (`feat:`, `fix:`, `docs:`, `test:`).
