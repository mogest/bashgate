# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Claude Code PreToolUse hook that screens bash commands before execution. It replaces `Bash(...)` permission rules in `settings.json` with a hook that also validates paths (since `permissionDecision: "allow"` bypasses Claude Code's own path-outside-cwd check).

The hook reads a JSON payload from stdin describing a Bash tool invocation, decides whether to allow it, and writes a JSON response to stdout with one of three outcomes: `"allow"`, `"ask"` (prompt the user), or no output (fall through to default behavior).

## Running Tests

```
.venv/bin/python -m pytest test_bashgate.py -v
```

Run a single test:

```
.venv/bin/python -m pytest test_bashgate.py -v -k test_name
```

The venv has pytest installed. No other dependencies are required.

## Configuration

The hook reads its allowlist from `~/.claude/bashgate.json` (global config) and any `.bashgate.json` files found by walking from the project's cwd upward to the filesystem root (local configs). All found configs are merged, with nearest-to-cwd having highest precedence.

Override with `--config <path>` to use only that single file (skips both global and local config discovery). If no config files are found, all commands fall through to the default permission system (nothing is auto-allowed).

### Config format

Top-level options:

- **`enabled`** (bool, default `true`): set to `false` to disable the hook entirely (fall through to defaults)
- **`disable_inside_sandbox`** (bool, default `false`): set to `true` to disable the hook when Claude Code's sandbox is active
- **`ignore_local_configs`** (bool, default `false`): set to `true` in the **global** config to skip local `.bashgate.json` discovery entirely. Prevents project-level configs from weakening or disabling protection.
- **`allowed_directories`** (string array): additional directories where path access is permitted, beyond the project cwd

Single `commands` array. Each entry is a **string** (simple prefix match) or an **object**:

```json
{
  "command": "<name>",
  "flags_with_args": ["<flags that consume next token>"],
  "allow": {
    "subcommands": ["<subcommand>" or {"subcommand": "...", ...}],
    "any_path": true | {"position": N},
    "flags_with_any_path": ["<flags exempt from path validation>"]
  },
  "deny": {
    "flags": ["<blocked flags>"],
    "arg_regex": "<pattern matched at argument boundaries>"
  }
}
```

All fields except `command` are optional. Subcommand entries mirror the same structure (with `subcommand` instead of `command`, and their own `allow`/`deny`).

### Config merging

When multiple config files are found, their `commands` arrays are merged:

- **Precedence order** (lowest → highest): global (`~/.claude/bashgate.json`), furthest ancestor, ..., parent, cwd
- **String entries** are keyed by the full string (e.g. `"cat"`, `"mise exec -- bundle exec rspec"`)
- **Object entries** are keyed by the `command` field (e.g. `"git"`, `"sed"`)
- A higher-precedence entry **replaces** a lower-precedence entry with the same key
- Non-overlapping entries from all configs are unioned together

### Matching rules

1. **String entry**: prefix match against the full command string
2. **Object without `allow.subcommands`**: match the `command` word, apply `deny` rules
3. **Object with `allow.subcommands`**: match the `command` word, find subcommand (first non-flag token not consumed by `flags_with_args`), match against allowed subcommands (longest prefix first). Unlisted subcommand → "ask"
4. **`deny.flags`**: block if any flag is present (exact match or `--flag=val` form)
5. **`deny.arg_regex`**: block if regex matches at argument boundaries (wrapped with `(?:^|\s)..(?:\s|$)`)
6. **`flags_with_args`**: these flags consume the next token — skip both when identifying the subcommand
7. **`allow.any_path`**: `true` disables path validation entirely; `{"position": N}` skips path validation for the Nth positional (non-flag) argument only (1-indexed, e.g. `{"position": 1}` for sed's expression argument)
8. **`allow.flags_with_any_path`**: exempt specific flags' values from path validation

## Architecture

Single-file tool (`bashgate.py`) with a test file (`test_bashgate.py`).

**Command processing pipeline** (`main()`):
1. Parse `--config` / `--validate` CLI flags
2. Handle `--validate` early return
3. Read JSON from stdin to get the command string and cwd
4. Bail out if `tool_name != "Bash"`
5. Load config: if `--config` was provided, load only that file; otherwise load global config + discover/load local configs via `find_local_configs(cwd)` and merge with `merge_commands()`
6. Parse merged config via `parse_config()`
7. Tokenize with `shlex` (punctuation_chars=True) to split on shell operators while respecting quoting
8. Reject dangerous tokens (`$`, backticks, `(`, `&`, etc.) via `find_dangerous_token()`
9. Split tokens at command separators (`&&`, `||`, `;`, `|`) into sub-commands via `split_on_operators()`
10. Check each sub-command via `check_command()` against the parsed config
11. For compound commands, all sub-commands must return "allow" or the whole command gets "ask"
12. For single commands, unrecognized commands produce no output (fall through)

**Config parsing** (`parse_config()`):
- `prefix_entries`: list of `(prefix_string, deny_config)` sorted longest-first, for string entries and objects without `allow.subcommands`
- `structured_entries`: dict of `command_name → parsed entry` for objects with `allow.subcommands` or `flags_with_args`

**Unified command checker** (`check_command()`):
1. Check redirect safety
2. Look up command in `structured_entries` — if found, use `find_subcommand()` to identify subcommand, match against `allow.subcommands`, apply command-level + subcommand-level deny rules
3. Otherwise try prefix matching via `prefix_entries`, apply deny rules
4. Run universal path validation (with `flags_with_any_path` exemptions)

**Path validation** (`find_path_outside_cwd()`): applies universally; checks non-flag tokens, `--flag=value` tokens, and `-Xvalue` short flag forms. Blocks absolute paths and `..` traversals that resolve outside cwd. `/dev/null` and other safe device paths are exempted.

**Tests** invoke the hook as a subprocess, writing the config to a temp file and passing `--config <path>`, then parsing JSON from stdout, matching the real hook protocol.
