#!/usr/bin/env python3
"""
Claude Code PreToolUse hook for screening bash commands.

Replaces Bash(...) permission rules in settings.json with a hook that also
validates paths, since permissionDecision "allow" bypasses Claude Code's
own path-outside-cwd check.

Commands are parsed with shlex to split compound commands at operator
boundaries. Each sub-command is checked against a configurable allowlist
loaded from ~/.claude/bashgate.json (or a path specified via
--config). Compound commands are allowed only if every sub-command is allowed.
"""

import json
import os
import re
import shlex
import shutil
import sys
from typing import NamedTuple

# ── Operator constants ──────────────────────────────────────────────────

COMMAND_SEPARATORS = frozenset({"&&", "||", ";", "|", "|&", "\n"})
DANGEROUS_PUNCTUATION = frozenset({"(", ")", ";;", ";&", ";;&", "<<", "<<<"})

# ── Safe device paths ──────────────────────────────────────────────────

SAFE_DEV_PATHS = frozenset({"/dev/null", "/dev/stderr", "/dev/stdout", "/dev/stdin"})

_debug = False


def detect_sandbox(cwd):
    """Detect if Claude Code's sandbox is enabled for the given project.

    Reads the project-local .claude/settings.local.json to check
    sandbox.enabled. Returns True if sandboxed, False otherwise.
    """
    settings_path = os.path.join(cwd, ".claude", "settings.local.json")
    try:
        with open(settings_path) as f:
            data = json.load(f)
        return bool(data.get("sandbox", {}).get("enabled", False))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False


def is_safe_dev_path(path):
    """Check if path is a safe device path (including /dev/fd/ on macOS)."""
    return path in SAFE_DEV_PATHS or path.startswith("/dev/fd/")


# ── Redirect operators ─────────────────────────────────────────────────

REDIRECT_OPERATORS = frozenset({">", ">>", "&>", "&>>"})

# ── Config validation ──────────────────────────────────────────────────


def _validate_string_list(value, path, errors):
    """Validate that value is a list of non-empty strings."""
    if not isinstance(value, list):
        errors.append(f"{path}: expected array, got {type(value).__name__}")
        return
    for i, item in enumerate(value):
        if not isinstance(item, str):
            errors.append(f"{path}[{i}]: expected string, got {type(item).__name__}")
        elif not item:
            errors.append(f"{path}[{i}]: empty string")


def _check_unknown_keys(obj, known_keys, path, errors):
    """Report any keys in obj not in known_keys."""
    for key in obj:
        if key not in known_keys:
            errors.append(f"{path}: unknown key {key!r}")


def _validate_rule(rule, path, errors):
    """Validate an ask or deny config object."""
    if not isinstance(rule, dict):
        errors.append(f"{path}: expected object, got {type(rule).__name__}")
        return
    _check_unknown_keys(rule, {"flags", "arg_regex", "message"}, path, errors)
    if "message" in rule:
        if not isinstance(rule["message"], str):
            errors.append(
                f"{path}.message: expected string, got {type(rule['message']).__name__}"
            )
        elif not rule["message"]:
            errors.append(f"{path}.message: empty string")
    if "flags" in rule:
        _validate_string_list(rule["flags"], f"{path}.flags", errors)
    if "arg_regex" in rule:
        raw = rule["arg_regex"]
        if not isinstance(raw, str):
            errors.append(
                f"{path}.arg_regex: expected string, got {type(raw).__name__}"
            )
        else:
            # Compile with the same boundary wrapping used at runtime
            m = re.match(r"^(\(\?[aiLmsux]+\))(.*)", raw, re.DOTALL)
            if m:
                flags_prefix, body = m.group(1), m.group(2)
            else:
                flags_prefix, body = "", raw
            pattern_str = flags_prefix + r"(?:^|\s)" + body + r"(?:\s|$)"
            try:
                re.compile(pattern_str)
            except re.error as e:
                errors.append(f"{path}.arg_regex: invalid regex {raw!r}: {e}")


def _validate_allow(allow, path, is_subcommand, errors):
    """Validate an allow config object."""
    if not isinstance(allow, dict):
        errors.append(f"{path}: expected object, got {type(allow).__name__}")
        return
    if is_subcommand:
        known = {"any_path", "flags_with_any_path"}
        if "subcommands" in allow:
            errors.append(f"{path}.subcommands: nested subcommands are not supported")
    else:
        known = {"subcommands", "any_path", "flags_with_any_path"}
    _check_unknown_keys(allow, known, path, errors)
    if "any_path" in allow:
        ap = allow["any_path"]
        if isinstance(ap, bool):
            pass
        elif isinstance(ap, dict):
            _check_unknown_keys(ap, {"position"}, f"{path}.any_path", errors)
            if "position" not in ap:
                errors.append(f"{path}.any_path: object must have 'position' key")
            elif not isinstance(ap["position"], int) or ap["position"] < 1:
                errors.append(f"{path}.any_path.position: expected positive integer")
        else:
            errors.append(
                f"{path}.any_path: expected boolean or object, got {type(ap).__name__}"
            )
    if "flags_with_any_path" in allow:
        _validate_string_list(
            allow["flags_with_any_path"], f"{path}.flags_with_any_path", errors
        )
    if "subcommands" in allow and not is_subcommand:
        subs = allow["subcommands"]
        if not isinstance(subs, list):
            errors.append(
                f"{path}.subcommands: expected array, got {type(subs).__name__}"
            )
        else:
            for i, entry in enumerate(subs):
                _validate_subcommand_entry(entry, f"{path}.subcommands[{i}]", errors)


def _validate_subcommand_entry(entry, path, errors):
    """Validate a subcommand entry (string or object)."""
    if isinstance(entry, str):
        if not entry:
            errors.append(f"{path}: empty string")
        return
    if not isinstance(entry, dict):
        errors.append(f"{path}: expected string or object, got {type(entry).__name__}")
        return
    _check_unknown_keys(entry, {"subcommand", "allow", "ask", "deny"}, path, errors)
    if "command" in entry and "subcommand" not in entry:
        errors.append(f"{path}: has 'command' key — did you mean 'subcommand'?")
        return
    if "subcommand" not in entry:
        errors.append(f"{path}: missing required key 'subcommand'")
        return
    if not isinstance(entry["subcommand"], str):
        errors.append(
            f"{path}.subcommand: expected string, got {type(entry['subcommand']).__name__}"
        )
    elif not entry["subcommand"]:
        errors.append(f"{path}.subcommand: empty string")
    if "allow" in entry:
        _validate_allow(
            entry["allow"], f"{path}.allow", is_subcommand=True, errors=errors
        )
    if "ask" in entry:
        _validate_rule(entry["ask"], f"{path}.ask", errors)
    if "deny" in entry:
        _validate_rule(entry["deny"], f"{path}.deny", errors)


def _validate_command_entry(entry, path, errors):
    """Validate a single command entry (string or object)."""
    if isinstance(entry, str):
        if not entry:
            errors.append(f"{path}: empty string")
        return
    if not isinstance(entry, dict):
        errors.append(f"{path}: expected string or object, got {type(entry).__name__}")
        return
    _check_unknown_keys(
        entry, {"command", "flags_with_args", "allow", "ask", "deny"}, path, errors
    )
    if "command" not in entry:
        errors.append(f"{path}: missing required key 'command'")
        return
    if not isinstance(entry["command"], str):
        errors.append(
            f"{path}.command: expected string, got {type(entry['command']).__name__}"
        )
    elif not entry["command"]:
        errors.append(f"{path}.command: empty string")
    if "flags_with_args" in entry:
        _validate_string_list(
            entry["flags_with_args"], f"{path}.flags_with_args", errors
        )
    if "allow" in entry:
        _validate_allow(
            entry["allow"], f"{path}.allow", is_subcommand=False, errors=errors
        )
    if "ask" in entry:
        _validate_rule(entry["ask"], f"{path}.ask", errors)
    if "deny" in entry:
        _validate_rule(entry["deny"], f"{path}.deny", errors)


def validate_config(data):
    """Validate a parsed config dict. Returns a list of error strings (empty = valid)."""
    errors = []
    if not isinstance(data, dict):
        errors.append(f"config: expected object, got {type(data).__name__}")
        return errors
    _check_unknown_keys(
        data,
        {"commands", "allowed_directories", "disable_inside_sandbox", "enabled", "ignore_local_configs"},
        "config",
        errors,
    )
    for bool_key in ("disable_inside_sandbox", "enabled", "ignore_local_configs"):
        if bool_key in data and not isinstance(data[bool_key], bool):
            errors.append(
                f"config.{bool_key}: expected boolean, got {type(data[bool_key]).__name__}"
            )
    commands = data.get("commands", [])
    if not isinstance(commands, list):
        errors.append(f"config.commands: expected array, got {type(commands).__name__}")
        return errors
    for i, entry in enumerate(commands):
        _validate_command_entry(entry, f"commands[{i}]", errors)
    if "allowed_directories" in data:
        _validate_string_list(
            data["allowed_directories"], "config.allowed_directories", errors
        )
    return errors


# ── Parsed config container ────────────────────────────────────────────


class ParsedConfig(NamedTuple):
    prefix_entries: list
    structured_entries: dict
    allowed_directories: list


# ── Config loading and parsing ─────────────────────────────────────────


def load_config(path):
    """Read JSON config. Missing file → empty result. Invalid JSON → stderr + exit 1.

    Returns (commands, allowed_directories, options) tuple where options is a dict
    with keys: disable_inside_sandbox (bool), enabled (bool).
    """
    default_options = {"disable_inside_sandbox": False, "enabled": True, "ignore_local_configs": False}
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return ([], [], default_options)
    except (json.JSONDecodeError, OSError) as e:
        fail(f"Error reading config {path}: {e}")
    errors = validate_config(data)
    if errors:
        for err in errors:
            print(f"Config error in {path}: {err}", file=sys.stderr)
        fail(f"Config error in {path}: {errors[0]}")
    config_dir = os.path.dirname(os.path.realpath(path))
    allowed_dirs = data.get("allowed_directories", [])
    resolved_dirs = []
    for d in allowed_dirs:
        if d.startswith("."):
            resolved_dirs.append(os.path.realpath(os.path.join(config_dir, d)))
        else:
            resolved_dirs.append(d)
    options = {
        "disable_inside_sandbox": data.get("disable_inside_sandbox", False),
        "enabled": data.get("enabled", True),
        "ignore_local_configs": data.get("ignore_local_configs", False),
    }
    return (data.get("commands", []), resolved_dirs, options)


def find_local_configs(cwd):
    """Walk from cwd up to filesystem root, collecting .bashgate.json paths.

    Returns list ordered furthest-ancestor-first (so highest precedence is last).
    """
    paths = []
    current = os.path.realpath(cwd)
    while True:
        candidate = os.path.join(current, ".bashgate.json")
        if os.path.isfile(candidate):
            paths.append(candidate)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    paths.reverse()
    return paths


def merge_commands(*commands_lists):
    """Merge multiple command lists by identity, last-wins.

    String entries are keyed by the full string.
    Object entries are keyed by the 'command' field.
    Higher-precedence lists should come later in the argument list.
    Returns the merged list preserving insertion order.
    """
    merged = {}
    for commands in commands_lists:
        for entry in commands:
            if isinstance(entry, str):
                key = entry
            else:
                key = entry["command"]
            merged[key] = entry
    return list(merged.values())


def merge_allowed_directories(*dirs_lists):
    """Merge multiple allowed_directories lists, deduplicating while preserving order."""
    seen = {}
    for dirs in dirs_lists:
        for d in dirs:
            if d not in seen:
                seen[d] = None
    return list(seen)


def _compile_rule(rule_dict):
    """Convert an ask/deny config dict into internal form with compiled regex.

    An empty dict is valid (unconditional rule with default message).
    Returns None only when rule_dict is None/falsy (i.e. the key was absent).
    """
    if rule_dict is None:
        return None
    result = {}
    if "flags" in rule_dict:
        result["flags"] = frozenset(rule_dict["flags"])
    if "arg_regex" in rule_dict:
        raw = rule_dict["arg_regex"]
        # Extract leading inline flags (e.g. (?i)) so they stay at the
        # start of the pattern after we prepend boundary matchers.
        m = re.match(r"^(\(\?[aiLmsux]+\))(.*)", raw, re.DOTALL)
        if m:
            flags_prefix, body = m.group(1), m.group(2)
        else:
            flags_prefix, body = "", raw
        pattern_str = flags_prefix + r"(?:^|\s)" + body + r"(?:\s|$)"
        result["arg_regex"] = re.compile(pattern_str)
    if "message" in rule_dict:
        result["message"] = rule_dict["message"]
    return result


def _parse_any_path(raw):
    """Parse any_path config value into internal form.

    Returns True (exempt all), False (no exemption), or frozenset of positions.
    """
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, dict):
        return frozenset({raw["position"]})
    return False


def _compile_rules(entry):
    """Compile ask and deny rules from an entry dict into a list of (compiled, decision).

    Deny rules are checked first (listed before ask rules).
    """
    rules = []
    deny = _compile_rule(entry.get("deny"))
    if deny is not None:
        rules.append((deny, "deny"))
    ask = _compile_rule(entry.get("ask"))
    if ask is not None:
        rules.append((ask, "ask"))
    return rules or None


def _parse_subcommand_entry(entry):
    """Parse a subcommand entry (string or dict) into (prefix, config_or_None)."""
    if isinstance(entry, str):
        return (entry, None)
    prefix = entry["subcommand"]
    config = {
        "rules": _compile_rules(entry),
        "any_path": _parse_any_path(entry.get("allow", {}).get("any_path", False)),
        "flags_with_any_path": frozenset(
            entry.get("allow", {}).get("flags_with_any_path", [])
        ),
    }
    return (prefix, config)


def parse_config(commands):
    """Convert JSON config into internal lookup structures.

    Returns (prefix_entries, structured_entries) where:
    - prefix_entries: list of (prefix_string, deny_config) sorted longest-first
    - structured_entries: dict of command_name → parsed entry dict
    """
    prefix_entries = []
    structured_entries = {}

    for entry in commands:
        if isinstance(entry, str):
            prefix_entries.append((entry, None))
            continue

        cmd = entry["command"]
        allow = entry.get("allow", {})
        has_subcommands = "subcommands" in allow
        has_flags_with_args = "flags_with_args" in entry
        has_any_path = allow.get("any_path", False) is not False
        has_flags_with_any_path = bool(allow.get("flags_with_any_path"))

        if (
            has_subcommands
            or has_flags_with_args
            or has_any_path
            or has_flags_with_any_path
        ):
            parsed_subs = None
            if has_subcommands:
                raw_subs = entry["allow"]["subcommands"]
                parsed_subs = [_parse_subcommand_entry(s) for s in raw_subs]
                parsed_subs.sort(key=lambda x: len(x[0]), reverse=True)

            structured_entries[cmd] = {
                "flags_with_args": entry.get("flags_with_args", []),
                "rules": _compile_rules(entry),
                "any_path": _parse_any_path(allow.get("any_path", False)),
                "flags_with_any_path": frozenset(allow.get("flags_with_any_path", [])),
                "subcommands": parsed_subs,
            }
        else:
            prefix_entries.append((cmd, _compile_rules(entry)))

    prefix_entries.sort(key=lambda x: len(x[0]), reverse=True)
    return prefix_entries, structured_entries


# ── Helper functions ─────────────────────────────────────────────────────


def find_subcommand(tokens, flags_with_args):
    """Identify subcommand by finding the first non-flag token.

    Skips tokens starting with '-'. For flags in flags_with_args, also
    skips the next token (consumed as the flag's value). Handles
    --flag=value and -Xvalue concatenated forms for flags_with_args.

    Returns the remaining tokens starting from the first non-flag token.
    """
    flags_set = set(flags_with_args) if flags_with_args else set()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if not token.startswith("-"):
            return tokens[i:]

        # Flag with separate value: -C dir
        if token in flags_set:
            i += 2
            continue

        # --flag=value form for flags_with_args
        if "=" in token:
            flag_part = token.split("=", 1)[0]
            if flag_part in flags_set:
                i += 1
                continue

        # Short flag concatenated form: -Cvalue
        for fwa in flags_with_args or []:
            if (
                len(fwa) == 2
                and fwa.startswith("-")
                and token.startswith(fwa)
                and len(token) > len(fwa)
            ):
                # Matched concatenated short flag (e.g. -Cvalue for -C);
                # break inner loop and fall through to i += 1 below
                break

        i += 1

    return []


def _check_single_rule(args, args_string, rule_config):
    """Check a single rule against arguments. Returns reason string or None."""
    custom_message = rule_config.get("message")

    # Unconditional rule (no flags or arg_regex configured)
    if not rule_config.get("flags") and not rule_config.get("arg_regex"):
        return custom_message or "Command blocked"

    blocked_flags = rule_config.get("flags", frozenset())
    if blocked_flags:
        for arg in args:
            if arg in blocked_flags:
                return custom_message or f"{arg} requires approval"
            if "=" in arg:
                flag_part = arg.split("=", 1)[0]
                if flag_part in blocked_flags:
                    return custom_message or f"{flag_part} requires approval"

    arg_regex = rule_config.get("arg_regex")
    if arg_regex:
        m = arg_regex.search(args_string)
        if m:
            return custom_message or f"Blocked argument: {m.group().strip()}"

    return None


def check_rules(args, args_string, rules):
    """Check ask/deny rules against arguments. Returns (reason, decision) or (None, None).

    rules is a list of (compiled_rule, decision_string) pairs, checked in order.
    """
    if not rules:
        return (None, None)

    for rule_config, decision in rules:
        reason = _check_single_rule(args, args_string, rule_config)
        if reason:
            return (reason, decision)

    return (None, None)


def find_path_outside_cwd(
    args, cwd, exempt_flags=None, allowed_directories=None, non_path_positions=None
):
    """Return the first arg that resolves to a path outside cwd, or None.

    Checks:
    1. Non-flag tokens: check the whole token
    2. --flag=value tokens: extract and check value
    3. -Xvalue short flags: if value starts with /, ~, or .., check it

    Flags in exempt_flags are excluded from checks 2 and 3.
    Paths under allowed_directories are permitted even if outside cwd.
    non_path_positions is an optional set of 1-indexed positional arg positions
    to skip during path validation (e.g. frozenset({1}) skips the first
    non-flag token).
    """
    if exempt_flags is None:
        exempt_flags = frozenset()
    cwd = os.path.realpath(cwd)
    resolved_allowed = []
    for d in allowed_directories or []:
        resolved_allowed.append(os.path.realpath(os.path.expanduser(d)))

    def is_outside(path_str):
        expanded = os.path.expanduser(path_str)
        if os.path.isabs(expanded) or ".." in expanded.split(os.sep):
            resolved = os.path.realpath(os.path.join(cwd, expanded))
            if is_safe_dev_path(path_str) or is_safe_dev_path(resolved):
                return False
            if not resolved.startswith(cwd + os.sep) and resolved != cwd:
                for allowed in resolved_allowed:
                    if resolved == allowed or resolved.startswith(allowed + os.sep):
                        return False
                return True
        return False

    pos_index = 0
    for arg in args:
        if not arg.startswith("-"):
            # Rule 1: non-flag token
            pos_index += 1
            if non_path_positions and pos_index in non_path_positions:
                continue
            if is_outside(arg):
                return arg
        elif arg.startswith("--") and "=" in arg:
            # Rule 2: --flag=value
            flag_part, value = arg.split("=", 1)
            if flag_part not in exempt_flags and is_outside(value):
                return value
        elif len(arg) > 2 and arg[0] == "-" and arg[1] != "-":
            # Rule 3: -Xvalue short flag
            flag_part = arg[:2]
            value = arg[2:]
            if (
                flag_part not in exempt_flags
                and (
                    value.startswith("/")
                    or value.startswith("~")
                    or value.startswith("..")
                )
                and is_outside(value)
            ):
                return value

    return None


def find_dangerous_redirect(parts):
    """Return a reason string if parts contain a redirect to an unsafe target."""
    for i, part in enumerate(parts):
        if part in REDIRECT_OPERATORS:
            if i + 1 < len(parts):
                target = parts[i + 1]
                if not is_safe_dev_path(target):
                    return f"Output redirect to: {target}"
            else:
                return "Output redirect with no target"
    return None


def _debug_write(message):
    """Append a line to the debug log if debug mode is enabled."""
    if _debug:
        debug_log = os.path.expanduser("~/.claude/bashgate-debug.log")
        with open(debug_log, "a") as f:
            f.write(message + "\n===\n")


def respond(decision, reason):
    _debug_write(f"DECISION: {decision} — {reason}")

    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        },
        sys.stdout,
    )


def fail(message):
    """Deny the tool call, log to stderr, and exit."""
    respond("deny", message)
    print(message, file=sys.stderr)
    sys.exit(1)


# ── Tokenization ────────────────────────────────────────────────────────


def tokenize(command):
    """Tokenize a command string using shlex with punctuation_chars=True.

    This splits on shell operators (&&, ||, ;, |, etc.) while respecting
    quoting and escaping. Newlines are treated as command separators (like
    bash) rather than whitespace. Returns a list of tokens.
    Raises ValueError if the command cannot be parsed (e.g. unclosed quotes).
    """
    lexer = shlex.shlex(command, posix=True, punctuation_chars="();<>|&\n")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    lexer.whitespace = " \t\r"
    return list(lexer)


def find_backtick_outside_single_quotes(command):
    """Check for backticks outside single-quoted strings in the raw command.

    Returns a reason string if a dangerous backtick is found, None otherwise.
    Single-quoted backticks are safe (literal). Double-quoted and unquoted are dangerous.
    """
    state = "unquoted"  # "unquoted", "single", "double"
    i = 0
    while i < len(command):
        ch = command[i]
        if state == "unquoted":
            if ch == "'":
                state = "single"
            elif ch == '"':
                state = "double"
            elif ch == "`":
                return "Backtick substitution outside single quotes"
        elif state == "single":
            if ch == "'":
                state = "unquoted"
            # No escaping in single quotes — POSIX rule
        elif state == "double":
            if ch == "\\" and i + 1 < len(command):
                i += 1  # skip escaped char
            elif ch == '"':
                state = "unquoted"
            elif ch == "`":
                return "Backtick substitution in double quotes"
        i += 1
    return None


def find_dangerous_token(tokens):
    """Scan tokens for dangerous shell constructs.

    Returns a reason string if a dangerous construct is found, None if clean.
    """
    for token in tokens:
        if "$" in token and not token.endswith("$"):
            return f"Variable/command expansion: {token}"
        if token in (">(", "<("):
            return f"Process substitution: {token}"
        if token in DANGEROUS_PUNCTUATION:
            return f"Shell construct: {token}"
        if token == "&":
            return "Background execution: &"
    return None


def split_on_operators(tokens):
    """Split a token list at command separators.

    Returns a list of sub-command token lists.
    E.g. ['git', 'status', '&&', 'git', 'diff'] -> [['git', 'status'], ['git', 'diff']]
    """
    commands = []
    current = []
    for token in tokens:
        if token in COMMAND_SEPARATORS:
            if current:
                commands.append(current)
            current = []
        else:
            current.append(token)
    if current:
        commands.append(current)
    return commands


# ── Command checker ──────────────────────────────────────────────────────


def check_command(parts, cwd, config: ParsedConfig):
    """Check a sub-command against config. Returns (decision, reason) or (None, None)."""
    if not parts:
        return (None, None)

    # Check for dangerous redirects
    redirect_issue = find_dangerous_redirect(parts)
    if redirect_issue:
        return ("ask", redirect_issue)

    prefix_entries = config.prefix_entries
    structured_entries = config.structured_entries
    allowed_directories = config.allowed_directories
    cmd = parts[0]

    # Try structured entries first
    if cmd in structured_entries:
        entry = structured_entries[cmd]
        rest = parts[1:]
        subcmd_tokens = find_subcommand(rest, entry["flags_with_args"])

        cmd_rules = entry["rules"]
        cmd_any_path = entry["any_path"]
        cmd_exempt_flags = entry["flags_with_any_path"]
        subcommands = entry["subcommands"]

        if subcommands is not None:
            # Match subcommand against allowed list (sorted longest-first)
            sub_str = " ".join(subcmd_tokens)
            matched = None

            for sub_prefix, sub_config in subcommands:
                if sub_str == sub_prefix or sub_str.startswith(sub_prefix + " "):
                    matched = (sub_prefix, sub_config)
                    break

            if matched is None:
                if subcmd_tokens:
                    return ("ask", f"{cmd} {subcmd_tokens[0]} requires approval")
                return ("ask", f"{cmd} requires approval")

            sub_prefix, sub_config = matched

            # Determine effective any_path and exempt_flags
            any_path = cmd_any_path
            exempt_flags = set(cmd_exempt_flags)
            sub_rules = None

            if sub_config:
                any_path = any_path or sub_config["any_path"]
                exempt_flags |= sub_config["flags_with_any_path"]
                sub_rules = sub_config["rules"]

            # Get sub-args (tokens after matched subcommand prefix)
            prefix_word_count = len(sub_prefix.split())
            sub_args = subcmd_tokens[prefix_word_count:]
            args_str = " ".join(sub_args)

            # Check command-level rules
            if cmd_rules:
                reason, decision = check_rules(sub_args, args_str, cmd_rules)
                if reason:
                    return (decision, f"{cmd} {sub_prefix}: {reason}")

            # Check subcommand-level rules
            if sub_rules:
                reason, decision = check_rules(sub_args, args_str, sub_rules)
                if reason:
                    return (decision, f"{cmd} {sub_prefix}: {reason}")

            # Path validation
            if any_path is not True:
                non_path_pos = any_path if isinstance(any_path, frozenset) else None
                outside = find_path_outside_cwd(
                    rest,
                    cwd,
                    exempt_flags,
                    allowed_directories,
                    non_path_positions=non_path_pos,
                )
                if outside:
                    return ("ask", f"Path outside working directory: {outside}")

            return ("allow", f"Allowed command: {cmd} {sub_prefix}")

        else:
            # Structured entry without subcommands (just flags_with_args and/or rules)
            any_path = cmd_any_path
            exempt_flags = cmd_exempt_flags

            if cmd_rules:
                args_str = " ".join(rest)
                reason, decision = check_rules(rest, args_str, cmd_rules)
                if reason:
                    return (decision, f"{cmd}: {reason}")

            if any_path is not True:
                non_path_pos = any_path if isinstance(any_path, frozenset) else None
                outside = find_path_outside_cwd(
                    rest,
                    cwd,
                    exempt_flags,
                    allowed_directories,
                    non_path_positions=non_path_pos,
                )
                if outside:
                    return ("ask", f"Path outside working directory: {outside}")

            return ("allow", f"Allowed command: {cmd}")

    # Try prefix matching
    full_cmd = " ".join(parts)
    for prefix, rules in prefix_entries:
        if full_cmd == prefix or full_cmd.startswith(prefix + " "):
            if rules:
                prefix_word_count = len(prefix.split())
                rest = parts[prefix_word_count:]
                args_str = " ".join(rest)
                reason, decision = check_rules(rest, args_str, rules)
                if reason:
                    return (decision, f"{parts[0]}: {reason}")

            outside = find_path_outside_cwd(
                parts, cwd, allowed_directories=allowed_directories
            )
            if outside:
                return ("ask", f"Path outside working directory: {outside}")

            return ("allow", f"Allowed command: {prefix}")

    return (None, None)


# ── Install command ───────────────────────────────────────────────────────

def _settings_path():
    return os.environ.get(
        "BASHGATE_SETTINGS_PATH",
        os.path.expanduser("~/.claude/settings.json"),
    )


def cmd_install():
    """Install bashgate as a PreToolUse hook in ~/.claude/settings.json."""
    settings_path = _settings_path()
    bashgate_path = os.path.realpath(sys.argv[0])
    quoted_path = shlex.quote(bashgate_path)
    hook_command = f"{quoted_path} hook"

    # Load existing settings
    try:
        with open(settings_path) as f:
            settings = json.load(f)
    except FileNotFoundError:
        settings = {}
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading {settings_path}: {e}", file=sys.stderr)
        sys.exit(1)

    hooks = settings.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("PreToolUse", [])

    # Find existing bashgate entry or create one
    bashgate_entry = None
    for entry in pre_tool_use:
        if entry.get("matcher") != "Bash":
            continue
        for hook in entry.get("hooks", []):
            if "bashgate" in hook.get("command", ""):
                bashgate_entry = hook
                break
        if bashgate_entry:
            break

    if bashgate_entry:
        old_command = bashgate_entry["command"]
        bashgate_entry["command"] = hook_command
        if old_command == hook_command:
            print(f"Already installed in {settings_path}")
        else:
            _write_settings(settings_path, settings)
            print(f"Updated hook command in {settings_path}")
            print(f"  was: {old_command}")
            print(f"  now: {hook_command}")
    else:
        # Create a new Bash matcher entry
        new_entry = {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": hook_command}],
        }
        pre_tool_use.append(new_entry)
        _write_settings(settings_path, settings)
        print(f"Installed hook in {settings_path}")
        print(f"  command: {hook_command}")

    # Copy default config if none exists
    config_path = os.path.expanduser("~/.claude/bashgate.json")
    if os.path.isfile(config_path):
        print(f"  config: {config_path}")
    else:
        default_config = os.path.join(os.path.dirname(os.path.realpath(__file__)), "bashgate.default.json")
        if os.path.isfile(default_config):
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            shutil.copy2(default_config, config_path)
            print(f"  config: {config_path} (created from default)")
        else:
            print(f"\nNote: No config found at {config_path}")
            print("Create one to define allowed commands. Without it, all commands fall through.")


def cmd_uninstall():
    """Remove bashgate hook from ~/.claude/settings.json."""
    settings_path = _settings_path()

    # Load existing settings
    try:
        with open(settings_path) as f:
            settings = json.load(f)
    except FileNotFoundError:
        print(f"No settings file found at {settings_path}")
        return
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading {settings_path}: {e}", file=sys.stderr)
        sys.exit(1)

    hooks = settings.get("hooks", {})
    pre_tool_use = hooks.get("PreToolUse", [])

    # Find and remove bashgate entries
    found = False
    new_pre_tool_use = []
    for entry in pre_tool_use:
        if entry.get("matcher") != "Bash":
            new_pre_tool_use.append(entry)
            continue
        original_hooks = entry.get("hooks", [])
        remaining_hooks = [
            h for h in original_hooks
            if "bashgate" not in h.get("command", "")
        ]
        if len(remaining_hooks) < len(original_hooks):
            found = True
        if remaining_hooks:
            entry["hooks"] = remaining_hooks
            new_pre_tool_use.append(entry)

    if not found:
        print(f"No bashgate hook found in {settings_path}")
    else:
        if new_pre_tool_use:
            hooks["PreToolUse"] = new_pre_tool_use
        else:
            hooks.pop("PreToolUse", None)
        if not hooks:
            settings.pop("hooks", None)
        _write_settings(settings_path, settings)
        print(f"Removed bashgate hook from {settings_path}")

    # Alert about config file
    config_path = os.path.expanduser("~/.claude/bashgate.json")
    if os.path.isfile(config_path):
        print(f"\nNote: Config file still exists at {config_path}")
        print("You may want to remove it manually if no longer needed.")


def _write_settings(path, settings):
    """Write settings JSON to the given path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")


# ── Main ─────────────────────────────────────────────────────────────────


def cmd_help():
    """Display usage information."""
    print("bashgate - Claude Code PreToolUse hook for screening bash commands")
    print()
    print("Commands:")
    print("  bashgate hook [options]   Run as a Claude Code PreToolUse hook (reads JSON from stdin)")
    print("  bashgate install          Install hook into ~/.claude/settings.json")
    print("  bashgate uninstall        Remove hook from ~/.claude/settings.json")
    print("  bashgate validate         Validate a config file")
    print()
    print("Hook options:")
    print("  --config <path>           Use only this config file (skip default discovery)")
    print("  --debug                   Enable debug logging to ~/.claude/bashgate-debug.log")
    print()
    print("Validate options:")
    print("  --config <path>           Config file to validate (default: ~/.claude/bashgate.json)")


def cmd_validate(args):
    """Validate a config file."""
    config_path = None
    i = 0
    while i < len(args):
        if args[i] == "--config" and i + 1 < len(args):
            config_path = args[i + 1]
            i += 2
        else:
            i += 1

    config_path = config_path or os.path.expanduser("~/.claude/bashgate.json")
    try:
        with open(config_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading config {config_path}: {e}", file=sys.stderr)
        sys.exit(1)
    errors = validate_config(data)
    if errors:
        for err in errors:
            print(f"{err}", file=sys.stderr)
        sys.exit(1)
    print(f"Config {config_path} is valid.")


def cmd_hook(args):
    """Run as a Claude Code PreToolUse hook."""
    global_config_path = os.environ.get(
        "BASHGATE_GLOBAL_CONFIG",
        os.path.expanduser("~/.claude/bashgate.json"),
    )
    explicit_config = None
    debug = False

    i = 0
    while i < len(args):
        if args[i] == "--config" and i + 1 < len(args):
            explicit_config = args[i + 1]
            i += 2
        elif args[i] == "--debug":
            debug = True
            i += 1
        else:
            i += 1

    global _debug
    _debug = debug

    # Read stdin early to get cwd for local config discovery
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as e:
        fail(f"bashgate: invalid JSON on stdin: {e}")

    if debug:
        debug_log = os.path.expanduser("~/.claude/bashgate-debug.log")
        with open(debug_log, "a") as f:
            f.write(json.dumps(data, indent=2) + "\n")
            f.write(
                f"sandbox_detected={detect_sandbox(data.get('cwd', os.getcwd()))}\n---\n"
            )

    # Only process Bash tool invocations
    if data.get("tool_name") != "Bash":
        _debug_write(f"SKIPPED: not a Bash tool call (tool_name={data.get('tool_name')!r})")
        return

    command = data.get("tool_input", {}).get("command", "").strip()
    cwd = data.get("cwd", os.getcwd())

    # Load and merge configs
    if explicit_config is not None:
        commands, allowed_directories, options = load_config(explicit_config)
    else:
        global_commands, global_allowed_dirs, global_options = load_config(
            global_config_path
        )
        if global_options.get("ignore_local_configs", False):
            commands = global_commands
            allowed_directories = global_allowed_dirs
            options = global_options
        else:
            local_paths = find_local_configs(cwd)
            local_results = [load_config(p) for p in local_paths]
            local_commands_lists = [r[0] for r in local_results]
            local_allowed_dirs_lists = [r[1] for r in local_results]
            commands = merge_commands(global_commands, *local_commands_lists)
            allowed_directories = merge_allowed_directories(
                global_allowed_dirs, *local_allowed_dirs_lists
            )
            # Nearest-to-cwd local config wins for each option key, else global
            options = dict(global_options)
            for r in local_results:
                options.update(r[2])

    # If disabled by config, fall through to default behavior
    if not options["enabled"]:
        _debug_write("SKIPPED: enabled=false in config, falling through")
        return

    # If sandbox mode is active and config opts in, fall through to default behavior
    if options["disable_inside_sandbox"] and detect_sandbox(cwd):
        _debug_write("SKIPPED: sandbox mode active, falling through")
        return

    prefix_entries, structured_entries = parse_config(commands)
    config = ParsedConfig(prefix_entries, structured_entries, allowed_directories)

    # Check for backticks outside single quotes on the raw command string
    # (must happen before shlex strips quotes)
    backtick_danger = find_backtick_outside_single_quotes(command)
    if backtick_danger:
        respond("ask", backtick_danger)
        return

    # Tokenize with shlex, respecting quotes and escaping
    try:
        tokens = tokenize(command)
    except ValueError:
        respond("ask", "Could not parse command")
        return

    if not tokens:
        _debug_write("SKIPPED: empty command")
        return

    # Check for dangerous shell constructs
    danger = find_dangerous_token(tokens)
    if danger:
        respond("ask", danger)
        return

    # Split at command separators and validate each sub-command
    sub_commands = split_on_operators(tokens)
    if not sub_commands:
        _debug_write("SKIPPED: no sub-commands after splitting")
        return

    is_compound = len(sub_commands) > 1

    decisions = []
    for parts in sub_commands:
        decision, reason = check_command(parts, cwd, config)
        decisions.append((decision, reason))

    if not is_compound:
        # Single command: preserve current behavior (allow/ask/fallthrough)
        decision, reason = decisions[0]
        if decision:
            respond(decision, reason)
        else:
            _debug_write(f"FALLTHROUGH: no matching rule for {sub_commands[0][0]!r}")
        return

    # Compound command: all must be "allow" for the compound to be allowed
    for i, (decision, reason) in enumerate(decisions):
        if decision in ("ask", "deny"):
            respond(decision, reason)
            return
        if decision is None:
            _debug_write(f"FALLTHROUGH: no matching rule for {sub_commands[i][0]!r} in compound command")
            return

    # All sub-commands returned "allow"
    reasons = [r for _, r in decisions]
    respond("allow", "All sub-commands allowed: " + "; ".join(reasons))


def main():
    subcommand = sys.argv[1] if len(sys.argv) > 1 else None
    rest = sys.argv[2:]

    if subcommand == "hook":
        cmd_hook(rest)
    elif subcommand == "install":
        cmd_install()
    elif subcommand == "uninstall":
        cmd_uninstall()
    elif subcommand == "validate":
        cmd_validate(rest)
    else:
        cmd_help()


if __name__ == "__main__":
    main()
