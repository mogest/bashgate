# bashgate

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) hook that automatically approves bash commands you've allowlisted, while still prompting for everything else. It also validates that file paths stay inside your project directory — something Claude Code's built-in `permissionDecision: "allow"` rules don't do.

## Why use this?

Claude Code asks permission before running bash commands. You can add `Bash(...)` rules in `settings.json` to auto-approve certain commands, but those rules bypass Claude Code's path validation — meaning an allowed command could read or write files anywhere on your system.

bashgate gives you the same auto-approval convenience with two improvements:

- **Path validation** — commands that reference paths outside your project directory are flagged for approval, even if the command itself is allowlisted
- **Fine-grained control** — allow specific subcommands (e.g. `git push` but not `git reset --hard`), block dangerous flags, and match argument patterns

## Installation

Requires Python 3.10+.

```sh
pipx install bashgate
bashgate install
```

`bashgate install` registers the hook in `~/.claude/settings.json` and copies a sensible default config to `~/.claude/bashgate.json` if one doesn't already exist.

## How it works

When Claude Code wants to run a bash command, bashgate intercepts it and makes one of three decisions:

- **Allow** — the command matches your allowlist and all paths are within the project directory
- **Ask** — the command is recognised but has a risky flag, targets a path outside the project, or hits a deny rule. Claude Code prompts you as normal
- **Fall through** — the command isn't in the config at all, so Claude Code's default permission system handles it

Compound commands (`&&`, `||`, `;`, `|`) are only auto-approved if every part is individually allowed. Shell features like variable expansion, backticks, and process substitution always trigger a prompt.

## Configuration

bashgate looks for config in two places:

1. **Global** — `~/.claude/bashgate.json`
2. **Local** — `.bashgate.json` files found by walking from the project directory up to the filesystem root

All found configs are merged, with the nearest-to-project file taking highest precedence. This lets you add project-specific rules (e.g. allowing `mix test` only in Elixir projects) on top of your global defaults.

If you don't want local configs to be able to weaken or disable your global rules, set `"ignore_local_configs": true` in your global config.

### Quick start

The default config (`bashgate.default.json`) ships with sensible rules for common commands. After `bashgate install`, you'll have a working setup that auto-approves things like `git status`, `ls`, `cat`, and `rg` while still prompting for destructive operations.

### Config format

The config is a JSON file with a `commands` array. Entries can be simple strings or detailed objects.

**Simple string** — prefix-matches the full command:

```json
{
  "commands": [
    "cat",
    "ls",
    "mise exec -- bundle exec rspec"
  ]
}
```

`"cat"` matches `cat foo.txt`, `cat -n bar.py`, etc.

**Object entry** — for commands that need subcommand control or deny rules:

```json
{
  "commands": [
    {
      "command": "git",
      "flags_with_args": ["-C", "-c"],
      "allow": {
        "subcommands": [
          "status",
          "diff",
          "log",
          {
            "subcommand": "push",
            "ask": {
              "flags": ["--force", "-f"]
            }
          }
        ]
      }
    }
  ]
}
```

This allows `git status`, `git diff`, `git log`, and `git push` — but prompts if `git push` is used with `--force`. Any other git subcommand (like `git reset`) falls through to Claude Code's default prompting.

### Entry reference

| Field | Description |
|---|---|
| `command` | The command name to match (required for object entries) |
| `flags_with_args` | Flags that consume the next token (e.g. `-C dir`) — needed so bashgate can correctly identify the subcommand |
| `allow.subcommands` | List of allowed subcommands (strings or objects with their own rules) |
| `allow.any_path` | `true` to skip path validation entirely, or `{"position": N}` to skip it for the Nth positional argument (useful for `sed` and `grep` where the first argument is a pattern, not a path) |
| `allow.flags_with_any_path` | Flags whose values should be exempt from path validation |
| `deny.flags` | Flags that should always be blocked |
| `deny.arg_regex` | Regex pattern matched against arguments — triggers a block if matched |
| `deny.message` | Custom message shown when a deny rule triggers |
| `ask.flags` | Flags that should trigger a prompt (same as deny but results in "ask" instead of "deny") |
| `ask.arg_regex` | Regex pattern that triggers a prompt if matched |

### Additional config options

| Field | Default | Description |
|---|---|---|
| `enabled` | `true` | Set to `false` to disable bashgate entirely (falls through to Claude Code defaults) |
| `disable_inside_sandbox` | `false` | Set to `true` to disable bashgate when Claude Code's sandbox is active |
| `ignore_local_configs` | `false` | Set to `true` in the **global** config to skip local `.bashgate.json` discovery entirely. Prevents project-level configs from weakening or disabling protection. |
| `allowed_directories` | `[]` | Additional directories that should be treated as valid path targets (supports relative paths resolved from the config file's location) |

## Security note: local config files

bashgate merges `.bashgate.json` files found in or above your project directory. This means a cloned repository could include a `.bashgate.json` that loosens your rules — for example, allowing commands or paths you wouldn't normally approve.

If you work with untrusted repositories, set `"ignore_local_configs": true` in your global `~/.claude/bashgate.json` to prevent any local config from being loaded.

## Validating your config

```sh
bashgate validate
bashgate validate --config path/to/config.json
```

This checks for structural errors, unknown keys, and invalid regex patterns.

## Uninstalling

```sh
bashgate uninstall
```

This removes the hook entry from `~/.claude/settings.json`. If `~/.claude/bashgate.json` exists, it will alert you but won't delete it — remove it manually if you no longer need it.

## `find` considered annoying

You'll find bashgate trips up on `find` quite a bit because of its awkward syntax.  I'd suggest

```
    {
      "command": "find",
      "deny": {
        "message": "use `fd` instead of `find`"
      }
    }
```

and install the excellent `fd` to do your finding for you instead.

## Debugging

If commands aren't being handled as expected:

```sh
# In your hook config, add --debug:
bashgate hook --debug
```

This logs decisions to `~/.claude/bashgate-debug.log`.

## License

MIT
