#!/usr/bin/env python3
"""Tests for bashgate.py hook."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HOOK = str(Path(__file__).parent / "bashgate.py")

sys.path.insert(0, str(Path(__file__).parent))
from importlib import import_module
_mod = import_module("bashgate")
sys.path.pop(0)

# Config used by tests — mirrors a typical user config for coverage.
TEST_CONFIG = {
    "commands": [
        "base64",
        "basename",
        "cat",
        "column",
        "comm",
        "cut",
        "date",
        "df",
        "diff",
        "diffstat",
        "dirname",
        "du",
        "echo",
        {"command": "fd", "ask": {"flags": ["-x", "--exec", "-X", "--exec-batch"]}},
        "file",
        {"command": "find", "ask": {"flags": ["-exec", "-execdir", "-ok", "-okdir", "-delete"]}},
        {
            "command": "gh",
            "allow": {
                "subcommands": [
                    {
                        "subcommand": "api",
                        "allow": {"any_path": True},
                        "ask": {
                            "flags": ["-f", "--field", "--raw-field", "--input"],
                            "arg_regex": "(?i)-(X|-method)[= ]?(POST|PUT|PATCH|DELETE)"
                        }
                    },
                    "pr diff",
                    "pr list",
                    "pr view",
                    "repo view"
                ]
            }
        },
        {
            "command": "git",
            "flags_with_args": ["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"],
            "allow": {
                "subcommands": [
                    "add",
                    "blame",
                    {"subcommand": "branch", "ask": {"flags": ["-d", "-D", "--delete", "-f", "--force", "-C", "-M"]}},
                    {"subcommand": "commit", "ask": {"flags": ["--amend"]}},
                    "diff",
                    "fetch",
                    "log",
                    "ls-files",
                    "ls-tree",
                    {
                        "subcommand": "push",
                        "ask": {
                            "flags": ["--force", "-f", "--force-with-lease", "--force-if-includes", "--delete", "-d", "--mirror", "--all", "--prune", "--no-verify"],
                            "arg_regex": ":[^\\s]+"
                        }
                    },
                    "reflog",
                    "rev-parse",
                    "show",
                    "status",
                    "tag"
                ]
            }
        },
        {
            "command": "go",
            "allow": {
                "subcommands": [
                    "build", "doc", "env", "fmt", "list",
                    "mod download", "mod graph", "mod tidy", "mod verify", "mod why",
                    "test", "version", "vet"
                ]
            }
        },
        "grep",
        "head",
        "jq",
        "ls",
        "md5",
        "mise exec -- bundle exec rspec",
        "mkdir",
        {
            "command": "mix",
            "allow": {
                "subcommands": [
                    "clean", "compile", "credo", "deps", "deps.compile", "deps.get",
                    "dialyzer", "format", "test"
                ]
            }
        },
        "nl",
        "od",
        "paste",
        "pbcopy",
        "printf",
        "pwd",
        "realpath",
        "rev",
        "rg",
        {"command": "sed", "allow": {"any_path": {"position": 1}}, "ask": {"arg_regex": "(?:-i\\S*|--in-place)"}},
        "seq",
        "shasum",
        "sort",
        "stat",
        "strings",
        "tail",
        "test",
        "tr",
        "tree",
        "uname",
        "uniq",
        "wc",
        "which",
        "whoami",
        "xxd"
    ]
}

_SENTINEL = object()


def run_hook(command, cwd="/tmp", tool_name="Bash", config=_SENTINEL, env=None):
    """Run the hook with a command and return (decision, reason) or (None, None).

    By default uses TEST_CONFIG. Pass config={"commands": [...]} to
    override, or config=None to use no config file at all (tests missing-file path).
    Pass env={"VAR": "val"} to add environment variables to the subprocess.
    """
    input_data = json.dumps({
        "tool_name": tool_name,
        "tool_input": {"command": command},
        "cwd": cwd,
    })

    extra_args = []
    tmp_path = None

    if config is None:
        # Point at a non-existent file to test missing-config behaviour
        extra_args = ["--config", "/tmp/_nonexistent_config_.json"]
    else:
        if config is _SENTINEL:
            config = TEST_CONFIG
        fd, tmp_path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(config, f)
        extra_args = ["--config", tmp_path]

    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    try:
        result = subprocess.run(
            [sys.executable, HOOK, "hook"] + extra_args,
            input=input_data,
            capture_output=True,
            text=True,
            env=run_env,
        )
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    if result.returncode != 0:
        return ("error", result.returncode)

    if not result.stdout.strip():
        return (None, None)
    output = json.loads(result.stdout)
    hook = output["hookSpecificOutput"]
    return (hook["permissionDecision"], hook["permissionDecisionReason"])


# ── Simple allowed commands ──────────────────────────────────────────────

def test_simple_git_status():
    assert run_hook("git status") == ("allow", "Allowed command: git status")

def test_simple_echo():
    assert run_hook("echo hello") == ("allow", "Allowed command: echo")

def test_simple_rg():
    assert run_hook("rg pattern") == ("allow", "Allowed command: rg")

def test_simple_git_commit():
    assert run_hook("git commit -m 'msg'") == ("allow", "Allowed command: git commit")

def test_simple_cat():
    assert run_hook("cat file.txt") == ("allow", "Allowed command: cat")


# ── Go commands ──────────────────────────────────────────────────────────

def test_go_build():
    assert run_hook("go build ./...") == ("allow", "Allowed command: go build")

def test_go_test():
    assert run_hook("go test ./...") == ("allow", "Allowed command: go test")

def test_go_test_verbose():
    assert run_hook("go test -v -run TestFoo ./pkg/...") == ("allow", "Allowed command: go test")

def test_go_vet():
    assert run_hook("go vet ./...") == ("allow", "Allowed command: go vet")

def test_go_fmt():
    assert run_hook("go fmt ./...") == ("allow", "Allowed command: go fmt")

def test_go_mod_tidy():
    assert run_hook("go mod tidy") == ("allow", "Allowed command: go mod tidy")

def test_go_mod_download():
    assert run_hook("go mod download") == ("allow", "Allowed command: go mod download")

def test_go_mod_graph():
    assert run_hook("go mod graph") == ("allow", "Allowed command: go mod graph")

def test_go_mod_verify():
    assert run_hook("go mod verify") == ("allow", "Allowed command: go mod verify")

def test_go_mod_why():
    assert run_hook("go mod why some/pkg") == ("allow", "Allowed command: go mod why")

def test_go_doc():
    assert run_hook("go doc fmt.Println") == ("allow", "Allowed command: go doc")

def test_go_env():
    assert run_hook("go env GOPATH") == ("allow", "Allowed command: go env")

def test_go_list():
    assert run_hook("go list ./...") == ("allow", "Allowed command: go list")

def test_go_version():
    assert run_hook("go version") == ("allow", "Allowed command: go version")

def test_go_run_not_allowed():
    """go run is an unlisted subcommand and should require approval."""
    decision, reason = run_hook("go run main.go")
    assert decision == "ask"
    assert "go run" in reason

def test_go_install_not_allowed():
    """go install is an unlisted subcommand and should require approval."""
    decision, reason = run_hook("go install ./...")
    assert decision == "ask"
    assert "go install" in reason

def test_go_generate_not_allowed():
    """go generate is an unlisted subcommand and should require approval."""
    decision, reason = run_hook("go generate ./...")
    assert decision == "ask"
    assert "go generate" in reason


# ── Compound allowed commands ────────────────────────────────────────────

def test_compound_git_status_and_diff():
    decision, _ = run_hook("git status && git diff")
    assert decision == "allow"

def test_compound_echo_pipe_pbcopy():
    decision, _ = run_hook("echo foo | pbcopy")
    assert decision == "allow"

def test_compound_git_log_pipe_head():
    decision, _ = run_hook("git log | head")
    assert decision == "allow"

def test_compound_git_add_and_commit():
    decision, _ = run_hook("git add file.txt && git commit -m 'msg'")
    assert decision == "allow"

def test_compound_three_commands():
    decision, _ = run_hook("git add . && git status && git diff")
    assert decision == "allow"

def test_compound_or_operator():
    decision, _ = run_hook("git status || echo failed")
    assert decision == "allow"

def test_compound_semicolon():
    decision, _ = run_hook("git status ; git diff")
    assert decision == "allow"

def test_compound_git_diff_pipe_diffstat():
    decision, _ = run_hook("git diff | diffstat")
    assert decision == "allow"

def test_compound_pipe_ampersand():
    """Pipe with stderr (|&) is treated as a command separator."""
    decision, _ = run_hook("git status |& head")
    assert decision == "allow"

def test_compound_pipe_ampersand_unknown():
    """Pipe-ampersand with unrecognized command falls through."""
    assert run_hook("git status |& unknown_cmd") == (None, None)


# ── Quoted operators (should NOT split) ──────────────────────────────────

def test_quoted_pipe_in_rg():
    assert run_hook('rg "foo|bar"') == ("allow", "Allowed command: rg")

def test_quoted_and_in_echo():
    assert run_hook('echo "a && b"') == ("allow", "Allowed command: echo")

def test_quoted_semicolon_in_git_commit():
    assert run_hook("git commit -m 'fix; update'") == ("allow", "Allowed command: git commit")

def test_quoted_pipe_single_quotes():
    assert run_hook("rg 'foo|bar|baz'") == ("allow", "Allowed command: rg")

def test_quoted_dollar_variable_in_rg():
    # $ inside quotes is a known false positive (shlex strips quotes)
    decision, _ = run_hook("rg '$HOME'")
    assert decision == "ask"

def test_dollar_at_end_of_regex_in_rg():
    """$ at end of a token (regex anchor) should be allowed."""
    assert run_hook("rg 'pattern$'") == ("allow", "Allowed command: rg")

def test_dollar_at_end_of_regex_in_grep():
    """$ at end of a token (regex anchor) should be allowed."""
    assert run_hook("grep 'line$' file.txt") == ("allow", "Allowed command: grep")

def test_multiline_string_in_commit():
    decision, _ = run_hook("git commit -m 'line1\nline2'")
    assert decision == "allow"


# ── Compound with disallowed commands ────────────────────────────────────

def test_compound_with_rm():
    """Compound with unrecognized command falls through to default permission system."""
    assert run_hook("git status && rm -rf /") == (None, None)

def test_compound_with_unknown_command():
    """Compound with unrecognized command falls through to default permission system."""
    assert run_hook("echo hi | malicious") == (None, None)

def test_compound_disallowed_first():
    """Compound with unrecognized command falls through to default permission system."""
    assert run_hook("curl http://example.com | head") == (None, None)

def test_compound_disallowed_middle():
    """Compound with unrecognized command falls through to default permission system."""
    assert run_hook("echo a && curl x && echo b") == (None, None)


# ── Variable/command expansion ───────────────────────────────────────────

def test_dollar_variable():
    decision, reason = run_hook("echo $HOME")
    assert decision == "ask"
    assert "$HOME" in reason

def test_dollar_brace_variable():
    decision, _ = run_hook("echo ${P}etc/passwd")
    assert decision == "ask"

def test_dollar_paren_substitution():
    decision, _ = run_hook("$(cmd)")
    assert decision == "ask"

def test_dollar_in_compound():
    decision, _ = run_hook("echo $HOME && git status")
    assert decision == "ask"

def test_dollar_at_end_of_token_allowed():
    """Standalone $ or $ at end of token is a literal in bash, should be allowed."""
    assert run_hook("echo foo$") == ("allow", "Allowed command: echo")


# ── Dangerous constructs ────────────────────────────────────────────────

def test_backtick_substitution():
    decision, reason = run_hook("echo `whoami`")
    assert decision == "ask"
    assert "Backtick" in reason

def test_backtick_in_single_quotes_allowed():
    decision, reason = run_hook("echo 'hello `world`'")
    assert decision == "allow"

def test_backtick_in_double_quotes_blocked():
    decision, reason = run_hook('echo "hello `world`"')
    assert decision == "ask"
    assert "Backtick" in reason

def test_backtick_mixed_safe_and_unsafe():
    decision, reason = run_hook("echo 'safe `' && echo `unsafe`")
    assert decision == "ask"
    assert "Backtick" in reason

def test_backslash_escaped_backtick_blocked():
    decision, reason = run_hook("echo \\`test\\`")
    assert decision == "ask"
    assert "Backtick" in reason

def test_backtick_single_quote_inside_double_quotes_no_escape():
    """A single quote inside double quotes must NOT switch to single-quote state."""
    decision, reason = run_hook("""echo "it's `bad`" """)
    assert decision == "ask"
    assert "Backtick" in reason

def test_backtick_adjacent_to_single_quoted_region():
    """After a single-quoted region ends, backticks are unquoted and dangerous."""
    decision, reason = run_hook("echo 'safe'`bad`")
    assert decision == "ask"
    assert "Backtick" in reason

def test_backtick_unclosed_single_quote():
    """Unclosed single quote: backtick check passes but shlex rejects the command."""
    decision, reason = run_hook("echo '`bad`")
    assert decision == "ask"
    assert "parse" in reason.lower()

def test_backtick_multiple_single_quoted_regions():
    """Backticks in separate single-quoted regions are all safe."""
    decision, reason = run_hook("echo '`one`' '`two`'")
    assert decision == "allow"

def test_background_execution():
    decision, reason = run_hook("cmd &")
    assert decision == "ask"
    assert "Background" in reason

def test_subshell_open_paren():
    decision, _ = run_hook("( echo hi )")
    assert decision == "ask"

def test_process_substitution_input():
    decision, _ = run_hook("diff <( cmd1 ) <( cmd2 )")
    assert decision == "ask"

def test_case_double_semicolon():
    decision, _ = run_hook("a ;; b")
    assert decision == "ask"


# ── Path validation ─────────────────────────────────────────────────────

def test_path_outside_cwd_simple():
    decision, reason = run_hook("cat /etc/passwd")
    assert decision == "ask"
    assert "/etc/passwd" in reason

def test_path_outside_cwd_compound():
    decision, reason = run_hook("cat /etc/passwd && echo hi")
    assert decision == "ask"
    assert "/etc/passwd" in reason

def test_git_path_outside_cwd():
    decision, _ = run_hook("git add /etc/passwd")
    assert decision == "ask"

def test_path_dotdot_outside():
    decision, _ = run_hook("cat ../../etc/passwd", cwd="/tmp/a/b")
    assert decision == "ask"

def test_dev_null_allowed():
    assert run_hook("cat /dev/null") == ("allow", "Allowed command: cat")

def test_dev_null_allowed_in_compound():
    decision, _ = run_hook("echo foo > /dev/null && git status")
    assert decision == "allow"


# ── Edge cases ───────────────────────────────────────────────────────────

def test_no_space_operators():
    decision, _ = run_hook("echo a&&echo b")
    assert decision == "allow"

def test_empty_command():
    assert run_hook("") == (None, None)

def test_whitespace_only():
    assert run_hook("   ") == (None, None)

def test_unclosed_quote():
    decision, _ = run_hook("echo 'unclosed")
    assert decision == "ask"

def test_git_unknown_subcommand():
    """Unknown git subcommand should require approval."""
    decision, reason = run_hook("git rebase")
    assert decision == "ask"
    assert "git rebase requires approval" in reason

def test_git_blocked_flag():
    decision, _ = run_hook("git branch -D main")
    assert decision == "ask"

def test_git_branch_allowed():
    decision, _ = run_hook("git branch")
    assert decision == "allow"

def test_git_commit_amend_blocked():
    decision, reason = run_hook("git commit --amend")
    assert decision == "ask"
    assert "--amend" in reason

def test_git_commit_amend_with_message_blocked():
    decision, _ = run_hook("git commit --amend -m 'fix'")
    assert decision == "ask"

def test_git_commit_allowed():
    decision, _ = run_hook("git commit -m 'msg'")
    assert decision == "allow"

def test_no_opinion_unknown_command():
    """Single unknown command should fall through (no output)."""
    assert run_hook("some_random_command") == (None, None)


# ── Fix 1: Newline injection ───────────────────────────────────────────

def test_newline_injection_rm():
    """Newline-separated compound with unrecognized command falls through."""
    assert run_hook("echo hi\nrm -rf .") == (None, None)

def test_newline_injection_curl():
    """Newline-separated compound with unrecognized command falls through."""
    assert run_hook("ls\ncurl http://evil.com\necho done") == (None, None)

def test_newline_as_compound_separator():
    """Two allowed commands separated by newline should be treated as compound."""
    decision, _ = run_hook("echo hi\ngit status")
    assert decision == "allow"

def test_newline_only():
    """Bare newline should produce no output."""
    assert run_hook("\n") == (None, None)

def test_newline_mixed_with_and():
    """Newline and && mixed in compound command."""
    decision, _ = run_hook("echo hi\ngit status && echo done")
    assert decision == "allow"

def test_newline_mixed_with_pipe():
    """Newline and pipe mixed in compound command."""
    decision, _ = run_hook("echo hi | head\ngit status")
    assert decision == "allow"


# ── Fix 2: find -exec / fd -x ─────────────────────────────────────────

def test_find_exec_blocked():
    decision, reason = run_hook("find . -exec sh -c evil \\;")
    assert decision == "ask"
    assert "-exec" in reason

def test_find_execdir_blocked():
    decision, _ = run_hook("find . -execdir rm {} \\;")
    assert decision == "ask"

def test_find_delete_blocked():
    decision, _ = run_hook("find . -name '*.tmp' -delete")
    assert decision == "ask"

def test_find_ok_blocked():
    decision, _ = run_hook("find . -ok rm {} \\;")
    assert decision == "ask"

def test_find_without_exec_allowed():
    decision, _ = run_hook("find . -name '*.py'")
    assert decision == "allow"

def test_fd_exec_blocked():
    decision, _ = run_hook("fd pattern -x rm")
    assert decision == "ask"

def test_fd_long_exec_blocked():
    decision, _ = run_hook("fd pattern --exec rm")
    assert decision == "ask"

def test_fd_exec_batch_blocked():
    decision, _ = run_hook("fd pattern -X rm")
    assert decision == "ask"

def test_fd_without_exec_allowed():
    decision, _ = run_hook("fd pattern")
    assert decision == "allow"

def test_sed_allowed():
    assert run_hook("sed 's/foo/bar/g' file.txt") == ("allow", "Allowed command: sed")

def test_sed_in_pipe():
    decision, _ = run_hook("echo hello | sed 's/hello/world/'")
    assert decision == "allow"

def test_sed_inplace_blocked():
    decision, reason = run_hook("sed -i 's/foo/bar/g' file.txt")
    assert decision == "ask"
    assert "-i" in reason

def test_sed_inplace_long_blocked():
    decision, reason = run_hook("sed --in-place 's/foo/bar/g' file.txt")
    assert decision == "ask"
    assert "--in-place" in reason

def test_sed_inplace_with_backup_blocked():
    """sed -i.bak should be caught by arg_regex matching -i variants."""
    decision, reason = run_hook("sed -i.bak 's/foo/bar/g' file.txt")
    assert decision == "ask"
    assert "-i.bak" in reason


def test_sed_address_expression_allowed():
    """sed address expressions starting with / should not be flagged as paths."""
    assert run_hook("sed '/pattern/d' file.txt") == ("allow", "Allowed command: sed")


def test_sed_address_expression_with_flag():
    """sed -n '/pattern/p' should work with address expressions."""
    assert run_hook("sed -n '/pattern/p' file.txt") == ("allow", "Allowed command: sed")


def test_sed_dotdot_in_regex():
    """sed regex containing .. (any two chars) should not be flagged."""
    assert run_hook("sed 's/../x/g' file.txt") == ("allow", "Allowed command: sed")


def test_sed_file_path_still_checked():
    """File arguments to sed should still be path-checked."""
    decision, reason = run_hook("sed 's/foo/bar/g' /etc/passwd")
    assert decision == "ask"
    assert "/etc/passwd" in reason


def test_sed_expression_exempt_but_file_checked():
    """Address expression is exempt but file path is still checked."""
    decision, reason = run_hook("sed '/pattern/d' /etc/passwd")
    assert decision == "ask"
    assert "/etc/passwd" in reason


# ── Fix 3: Tilde path bypass ──────────────────────────────────────────

def test_tilde_read_sensitive_file():
    decision, reason = run_hook("cat ~/.ssh/id_rsa")
    assert decision == "ask"
    assert "~/.ssh/id_rsa" in reason

def test_tilde_write_bashrc():
    decision, _ = run_hook("echo payload >> ~/.bashrc")
    assert decision == "ask"

def test_tilde_in_compound():
    decision, _ = run_hook("cat ~/.ssh/id_rsa | pbcopy")
    assert decision == "ask"

def test_tilde_git_path():
    decision, _ = run_hook("git add ~/.ssh/id_rsa")
    assert decision == "ask"


# ── Fix 4: Redirect operators ─────────────────────────────────────────

def test_redirect_to_file():
    decision, reason = run_hook("echo payload > evil.sh")
    assert decision == "ask"
    assert "redirect" in reason.lower()

def test_redirect_append_to_file():
    decision, _ = run_hook("echo payload >> evil.sh")
    assert decision == "ask"

def test_redirect_to_dev_null():
    decision, _ = run_hook("echo foo > /dev/null")
    assert decision == "allow"

def test_redirect_to_dev_stderr():
    decision, _ = run_hook("echo foo > /dev/stderr")
    assert decision == "allow"

def test_redirect_to_dev_stdout():
    decision, _ = run_hook("echo foo > /dev/stdout")
    assert decision == "allow"

def test_redirect_stderr_to_dev_null():
    """2>/dev/null should be allowed."""
    decision, _ = run_hook("git status 2> /dev/null")
    assert decision == "allow"

def test_redirect_to_tilde_path():
    decision, _ = run_hook("cat file.txt > ~/Desktop/exfil.txt")
    assert decision == "ask"

def test_redirect_git_diff_to_file():
    decision, _ = run_hook("git diff > patch.txt")
    assert decision == "ask"

def test_redirect_ampersand_gt():
    """&> redirect should be checked."""
    decision, _ = run_hook("echo foo &> evil.sh")
    assert decision == "ask"

def test_redirect_ampersand_gt_dev_null():
    decision, _ = run_hook("echo foo &> /dev/null")
    assert decision == "allow"


# ── Fix 5: Git --git-dir / --work-tree bypass ─────────────────────────

def test_git_gitdir_outside_cwd():
    decision, reason = run_hook("git --git-dir=../../other/.git log")
    assert decision == "ask"
    assert "outside" in reason.lower()

def test_git_worktree_outside_cwd():
    decision, _ = run_hook("git --work-tree=../../other log")
    assert decision == "ask"

def test_git_C_with_space_outside_cwd():
    decision, _ = run_hook("git -C ../../other status")
    assert decision == "ask"

def test_git_C_concatenated_outside_cwd():
    decision, _ = run_hook("git -C../../other status")
    assert decision == "ask"

def test_git_gitdir_inside_cwd():
    """--git-dir within cwd should be allowed."""
    decision, _ = run_hook("git --git-dir=.git log", cwd="/tmp")
    assert decision == "allow"


# ── Fix 6: Heredoc parsing ────────────────────────────────────────────

def test_heredoc_blocked():
    decision, reason = run_hook("cat << EOF")
    assert decision == "ask"
    assert "<<" in reason

def test_herestring_blocked():
    decision, _ = run_hook("cat <<< input")
    assert decision == "ask"


# ── Fix 7: Safe dev paths ─────────────────────────────────────────────

def test_dev_stderr_not_flagged():
    """Redirect to /dev/stderr should not be flagged as outside cwd."""
    decision, _ = run_hook("echo error > /dev/stderr")
    assert decision == "allow"

def test_dev_stdout_not_flagged():
    decision, _ = run_hook("echo msg > /dev/stdout")
    assert decision == "allow"

def test_dev_stdin_as_arg():
    """Using /dev/stdin as an argument should be allowed."""
    decision, _ = run_hook("cat /dev/stdin")
    assert decision == "allow"


# ── Fix 10: tool_name validation ──────────────────────────────────────

def test_non_bash_tool_falls_through():
    """Non-Bash tools should not be filtered."""
    assert run_hook("rm -rf /", tool_name="Write") == (None, None)

def test_missing_tool_name_falls_through():
    """Missing tool_name should not be filtered."""
    assert run_hook("rm -rf /", tool_name="") == (None, None)


# ── gh command handling ─────────────────────────────────────────────────

# gh api GET requests (default and explicit)

def test_gh_api_default_get():
    assert run_hook("gh api /repos/owner/repo") == ("allow", "Allowed command: gh api")

def test_gh_api_explicit_get():
    assert run_hook("gh api -X GET /repos/owner/repo") == ("allow", "Allowed command: gh api")

def test_gh_api_method_flag_get():
    assert run_hook("gh api --method GET /repos/owner/repo") == ("allow", "Allowed command: gh api")

def test_gh_api_method_equals_get():
    assert run_hook("gh api --method=GET /repos/owner/repo") == ("allow", "Allowed command: gh api")

# gh api mutating methods (explicit)

def test_gh_api_post():
    decision, reason = run_hook("gh api -X POST /repos/owner/repo/issues")
    assert decision == "ask"
    assert "POST" in reason

def test_gh_api_put():
    decision, reason = run_hook("gh api -X PUT /repos/owner/repo")
    assert decision == "ask"
    assert "PUT" in reason

def test_gh_api_patch():
    decision, reason = run_hook("gh api -X PATCH /repos/owner/repo")
    assert decision == "ask"
    assert "PATCH" in reason

def test_gh_api_delete():
    decision, reason = run_hook("gh api -X DELETE /repos/owner/repo")
    assert decision == "ask"
    assert "DELETE" in reason

def test_gh_api_method_flag_post():
    decision, _ = run_hook("gh api --method POST /repos/owner/repo/issues")
    assert decision == "ask"

def test_gh_api_method_equals_post():
    decision, _ = run_hook("gh api --method=POST /repos/owner/repo/issues")
    assert decision == "ask"

def test_gh_api_dash_x_post_concatenated():
    decision, _ = run_hook("gh api -XPOST /repos/owner/repo/issues")
    assert decision == "ask"

# gh api POST inference from flags

def test_gh_api_field_flag():
    decision, _ = run_hook("gh api /repos/owner/repo/issues -f title=bug")
    assert decision == "ask"

def test_gh_api_long_field_flag():
    decision, _ = run_hook("gh api /repos/owner/repo/issues --field title=bug")
    assert decision == "ask"

def test_gh_api_field_equals_form():
    decision, _ = run_hook("gh api /repos/owner/repo/issues --field=title=bug")
    assert decision == "ask"

def test_gh_api_raw_field_flag():
    decision, _ = run_hook("gh api /repos/owner/repo/issues --raw-field body=text")
    assert decision == "ask"

def test_gh_api_raw_field_equals_form():
    decision, _ = run_hook("gh api /repos/owner/repo/issues --raw-field=body=text")
    assert decision == "ask"

def test_gh_api_input_flag():
    decision, _ = run_hook("gh api /repos/owner/repo/issues --input file.json")
    assert decision == "ask"

def test_gh_api_input_equals_form():
    decision, _ = run_hook("gh api /repos/owner/repo/issues --input=file.json")
    assert decision == "ask"

# gh api path not flagged as filesystem path

def test_gh_api_path_not_flagged():
    """API paths like /repos/owner/repo should not be flagged as filesystem paths."""
    assert run_hook("gh api /repos/owner/repo") == ("allow", "Allowed command: gh api")

# gh api compound commands

def test_gh_api_pipe_jq():
    decision, _ = run_hook("gh api /repos/owner/repo | jq .name")
    assert decision == "allow"

def test_gh_api_and_echo():
    decision, _ = run_hook("gh api /repos/owner/repo && echo done")
    assert decision == "allow"

# Existing allowed gh commands

def test_gh_pr_diff():
    assert run_hook("gh pr diff 123") == ("allow", "Allowed command: gh pr diff")

def test_gh_pr_list():
    assert run_hook("gh pr list") == ("allow", "Allowed command: gh pr list")

def test_gh_pr_view():
    assert run_hook("gh pr view 123") == ("allow", "Allowed command: gh pr view")

def test_gh_repo_view():
    assert run_hook("gh repo view owner/repo") == ("allow", "Allowed command: gh repo view")

# gh edge cases

def test_gh_unknown_subcommand():
    """Unknown gh subcommand should require approval."""
    decision, reason = run_hook("gh issue create")
    assert decision == "ask"
    assert "gh issue requires approval" in reason

def test_gh_no_args():
    """gh with no args should require approval."""
    decision, reason = run_hook("gh")
    assert decision == "ask"
    assert "gh requires approval" in reason

def test_gh_api_no_args():
    """gh api with no args defaults to allowed (no deny triggered)."""
    assert run_hook("gh api") == ("allow", "Allowed command: gh api")


# ── Fix 11: Comment lines in commands ──────────────────────────────────

def test_comment_with_apostrophe():
    """Comment lines with apostrophes (what's, let's) should not cause parse errors."""
    assert run_hook("# Check what's in the module\nfd -t f brotli") == ("allow", "Allowed command: fd")

def test_comment_with_lets():
    assert run_hook("# The js/ subfolder has app.js - let's check that too\nls -lh dir/") == ("allow", "Allowed command: ls")

def test_comment_only():
    """A command that is only a comment should fall through."""
    assert run_hook("# just a comment") == (None, None)

def test_quoted_hash_still_works():
    """# inside quotes should not be treated as a comment."""
    assert run_hook("rg '#include' file.c") == ("allow", "Allowed command: rg")


# ── Config file handling ────────────────────────────────────────────────

def test_missing_config_all_commands_fall_through():
    """Missing config file → empty allowlist → all commands fall through."""
    assert run_hook("git status", config=None) == (None, None)

def test_missing_config_dangerous_still_blocked():
    """Missing config file still blocks dangerous shell constructs."""
    decision, _ = run_hook("echo $HOME", config=None)
    assert decision == "ask"

def test_invalid_json_config():
    """Invalid JSON config → exit code 1."""
    fd, tmp_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        f.write("{invalid json")

    input_data = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "cwd": "/tmp",
    })
    try:
        result = subprocess.run(
            [sys.executable, HOOK, "hook", "--config", tmp_path],
            input=input_data,
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(tmp_path)

    assert result.returncode == 1

def test_custom_config_allowlist():
    """Custom config with only 'ls' allowed."""
    config = {"commands": ["ls"]}
    assert run_hook("ls -la", config=config) == ("allow", "Allowed command: ls")
    assert run_hook("cat file.txt", config=config) == (None, None)
    assert run_hook("git status", config=config) == (None, None)


# ── deny.arg_regex matching ─────────────────────────────────────────────

def test_arg_regex_blocks_post_method():
    """arg_regex should block -X POST."""
    decision, reason = run_hook("gh api -X POST /repos/owner/repo/issues")
    assert decision == "ask"
    assert "POST" in reason

def test_arg_regex_allows_get_method():
    """arg_regex should not block -X GET."""
    decision, _ = run_hook("gh api -X GET /repos/owner/repo")
    assert decision == "allow"

def test_arg_regex_blocks_concatenated_method():
    """arg_regex should block -XDELETE."""
    decision, reason = run_hook("gh api -XDELETE /repos/owner/repo")
    assert decision == "ask"
    assert "DELETE" in reason

def test_arg_regex_blocks_method_equals():
    """arg_regex should block --method=PUT."""
    decision, reason = run_hook("gh api --method=PUT /repos/owner/repo")
    assert decision == "ask"
    assert "PUT" in reason


# ── flags_with_args subcommand identification ───────────────────────────

def test_flags_with_args_skips_C_flag():
    """git -C dir status should identify 'status' as subcommand."""
    decision, _ = run_hook("git -C . status", cwd="/tmp")
    assert decision == "allow"

def test_flags_with_args_skips_gitdir_equals():
    """git --git-dir=.git log should identify 'log' as subcommand."""
    decision, _ = run_hook("git --git-dir=.git log", cwd="/tmp")
    assert decision == "allow"

def test_flags_with_args_skips_config():
    """git -c key=val status should identify 'status' as subcommand."""
    decision, _ = run_hook("git -c core.pager=cat status", cwd="/tmp")
    assert decision == "allow"

def test_flags_with_args_skips_no_pager():
    """git --no-pager log should identify 'log' (skip boolean flag)."""
    decision, _ = run_hook("git --no-pager log", cwd="/tmp")
    assert decision == "allow"


# ── allow.any_path ──────────────────────────────────────────────────────

def test_any_path_disables_path_validation():
    """gh api with absolute API paths should not trigger path validation."""
    assert run_hook("gh api /repos/owner/repo") == ("allow", "Allowed command: gh api")

def test_any_path_does_not_affect_other_subcommands():
    """gh pr view with absolute path should still be blocked."""
    decision, reason = run_hook("gh pr view /etc/passwd")
    assert decision == "ask"
    assert "outside" in reason.lower()


# ── allow.flags_with_any_path ───────────────────────────────────────────

def test_flags_with_any_path_exemption():
    """Flags listed in flags_with_any_path should not trigger path validation."""
    config = {
        "commands": [
            {
                "command": "mycmd",
                "allow": {
                    "subcommands": [
                        {
                            "subcommand": "run",
                            "allow": {"flags_with_any_path": ["--template"]}
                        }
                    ]
                }
            }
        ]
    }
    # --template=/etc/foo should be exempt from path validation
    decision, _ = run_hook("mycmd run --template=/etc/foo", config=config, cwd="/tmp")
    assert decision == "allow"

def test_flags_with_any_path_non_exempt_still_blocked():
    """Non-exempt flags with outside paths should still be blocked."""
    config = {
        "commands": [
            {
                "command": "mycmd",
                "allow": {
                    "subcommands": [
                        {
                            "subcommand": "run",
                            "allow": {"flags_with_any_path": ["--template"]}
                        }
                    ]
                }
            }
        ]
    }
    # --config=/etc/foo should NOT be exempt
    decision, _ = run_hook("mycmd run --config=/etc/foo", config=config, cwd="/tmp")
    assert decision == "ask"


# ── Enhanced path validation ────────────────────────────────────────────

def test_path_validation_flag_equals_outside():
    """--flag=/outside/path should be caught."""
    decision, reason = run_hook("git log --output=/etc/passwd", cwd="/tmp")
    assert decision == "ask"
    assert "/etc/passwd" in reason

def test_path_validation_short_flag_outside():
    """-C/outside/path should be caught."""
    decision, _ = run_hook("git -C/etc status", cwd="/tmp")
    assert decision == "ask"

def test_path_validation_short_flag_dotdot():
    """-C../../other should be caught."""
    decision, _ = run_hook("git -C../../other status", cwd="/tmp/a/b")
    assert decision == "ask"


## ── Config validation ──────────────────────────────────────────────────

validate_config = _mod.validate_config
_parse_any_path = _mod._parse_any_path


def test_parse_any_path():
    assert _parse_any_path(True) is True
    assert _parse_any_path(False) is False
    assert _parse_any_path({"position": 1}) == frozenset({1})
    assert _parse_any_path({"position": 3}) == frozenset({3})


# ── Valid configs ────────────────────────────────────────────────────────

def test_validate_test_config():
    """TEST_CONFIG should validate without errors."""
    assert validate_config(TEST_CONFIG) == []

def test_validate_minimal_config():
    """Minimal valid config: empty commands list."""
    assert validate_config({"commands": []}) == []

def test_validate_string_entries():
    assert validate_config({"commands": ["ls", "cat", "echo"]}) == []

def test_validate_full_featured_config():
    """A config exercising all features should validate."""
    config = {
        "commands": [
            "echo",
            {"command": "find", "ask": {"flags": ["-exec"], "arg_regex": "dangerous"}},
            {
                "command": "git",
                "flags_with_args": ["-C"],
                "allow": {
                    "subcommands": [
                        "status",
                        {
                            "subcommand": "api",
                            "allow": {"any_path": True, "flags_with_any_path": ["--template"]},
                            "ask": {"flags": ["-f"], "arg_regex": "(?i)POST"}
                        }
                    ]
                }
            }
        ]
    }
    assert validate_config(config) == []


# ── Missing required keys ────────────────────────────────────────────────

def test_validate_missing_commands_key():
    errors = validate_config({})
    assert len(errors) == 0

def test_validate_missing_command_key():
    errors = validate_config({"commands": [{"ask": {"flags": ["-x"]}}]})
    assert any("'command'" in e for e in errors)

def test_validate_missing_subcommand_key():
    config = {"commands": [
        {"command": "git", "allow": {"subcommands": [{"ask": {"flags": ["-f"]}}]}}
    ]}
    errors = validate_config(config)
    assert any("'subcommand'" in e for e in errors)


# ── Type errors ──────────────────────────────────────────────────────────

def test_validate_config_not_dict():
    errors = validate_config("not a dict")
    assert any("expected object" in e for e in errors)

def test_validate_commands_not_list():
    errors = validate_config({"commands": "not a list"})
    assert any("expected array" in e for e in errors)

def test_validate_entry_wrong_type():
    errors = validate_config({"commands": [42]})
    assert any("expected string or object" in e for e in errors)

def test_validate_command_name_not_string():
    errors = validate_config({"commands": [{"command": 42}]})
    assert any("expected string" in e for e in errors)

def test_validate_ask_not_dict():
    errors = validate_config({"commands": [{"command": "x", "ask": "bad"}]})
    assert any("expected object" in e for e in errors)

def test_validate_deny_not_dict():
    errors = validate_config({"commands": [{"command": "x", "deny": "bad"}]})
    assert any("expected object" in e for e in errors)

def test_validate_ask_flags_not_list():
    errors = validate_config({"commands": [{"command": "x", "ask": {"flags": "bad"}}]})
    assert any("expected array" in e for e in errors)

def test_validate_deny_flags_not_list():
    errors = validate_config({"commands": [{"command": "x", "deny": {"flags": "bad"}}]})
    assert any("expected array" in e for e in errors)

def test_validate_ask_flags_item_not_string():
    errors = validate_config({"commands": [{"command": "x", "ask": {"flags": [1]}}]})
    assert any("expected string" in e for e in errors)

def test_validate_arg_regex_not_string():
    errors = validate_config({"commands": [{"command": "x", "ask": {"arg_regex": 42}}]})
    assert any("expected string" in e for e in errors)

def test_validate_allow_not_dict():
    errors = validate_config({"commands": [{"command": "x", "allow": "bad"}]})
    assert any("expected object" in e for e in errors)

def test_validate_any_path_not_bool():
    config = {"commands": [
        {"command": "x", "allow": {"subcommands": [
            {"subcommand": "y", "allow": {"any_path": "yes"}}
        ]}}
    ]}
    errors = validate_config(config)
    assert any("expected boolean or object" in e for e in errors)


def test_validate_any_path_position_valid():
    config = {"commands": [
        {"command": "sed", "allow": {"any_path": {"position": 1}}}
    ]}
    assert validate_config(config) == []


def test_validate_any_path_position_zero():
    config = {"commands": [
        {"command": "sed", "allow": {"any_path": {"position": 0}}}
    ]}
    errors = validate_config(config)
    assert any("positive integer" in e for e in errors)


def test_validate_any_path_position_negative():
    config = {"commands": [
        {"command": "sed", "allow": {"any_path": {"position": -1}}}
    ]}
    errors = validate_config(config)
    assert any("positive integer" in e for e in errors)


def test_validate_any_path_position_not_int():
    config = {"commands": [
        {"command": "sed", "allow": {"any_path": {"position": "one"}}}
    ]}
    errors = validate_config(config)
    assert any("positive integer" in e for e in errors)


def test_validate_any_path_dict_missing_position():
    config = {"commands": [
        {"command": "sed", "allow": {"any_path": {"offset": 1}}}
    ]}
    errors = validate_config(config)
    assert any("'position' key" in e for e in errors)


def test_validate_any_path_dict_unknown_key():
    config = {"commands": [
        {"command": "sed", "allow": {"any_path": {"position": 1, "extra": True}}}
    ]}
    errors = validate_config(config)
    assert any("unknown key" in e for e in errors)


def test_validate_subcommands_not_list():
    errors = validate_config({"commands": [{"command": "x", "allow": {"subcommands": "bad"}}]})
    assert any("expected array" in e for e in errors)

def test_validate_subcommand_entry_wrong_type():
    config = {"commands": [{"command": "x", "allow": {"subcommands": [42]}}]}
    errors = validate_config(config)
    assert any("expected string or object" in e for e in errors)

def test_validate_subcommand_name_not_string():
    config = {"commands": [{"command": "x", "allow": {"subcommands": [{"subcommand": 42}]}}]}
    errors = validate_config(config)
    assert any("expected string" in e for e in errors)

def test_validate_flags_with_args_not_list():
    errors = validate_config({"commands": [{"command": "x", "flags_with_args": "bad"}]})
    assert any("expected array" in e for e in errors)

def test_validate_flags_with_any_path_not_list():
    config = {"commands": [
        {"command": "x", "allow": {"subcommands": [
            {"subcommand": "y", "allow": {"flags_with_any_path": "bad"}}
        ]}}
    ]}
    errors = validate_config(config)
    assert any("expected array" in e for e in errors)


# ── Unknown keys ─────────────────────────────────────────────────────────

def test_validate_unknown_top_level_key():
    errors = validate_config({"commands": [], "extra": True})
    assert any("unknown key 'extra'" in e for e in errors)

def test_validate_unknown_command_key():
    errors = validate_config({"commands": [{"command": "x", "subcmds": []}]})
    assert any("unknown key 'subcmds'" in e for e in errors)

def test_validate_unknown_ask_key():
    errors = validate_config({"commands": [{"command": "x", "ask": {"flags": [], "regex": "x"}}]})
    assert any("unknown key 'regex'" in e for e in errors)

def test_validate_unknown_deny_key():
    errors = validate_config({"commands": [{"command": "x", "deny": {"flags": [], "regex": "x"}}]})
    assert any("unknown key 'regex'" in e for e in errors)

def test_validate_unknown_allow_key():
    errors = validate_config({"commands": [{"command": "x", "allow": {"paths": True}}]})
    assert any("unknown key 'paths'" in e for e in errors)

def test_validate_unknown_subcommand_key():
    config = {"commands": [
        {"command": "x", "allow": {"subcommands": [{"subcommand": "y", "extra": True}]}}
    ]}
    errors = validate_config(config)
    assert any("unknown key 'extra'" in e for e in errors)


# ── Regex validation ─────────────────────────────────────────────────────

def test_validate_invalid_regex():
    errors = validate_config({"commands": [{"command": "x", "ask": {"arg_regex": "[bad"}}]})
    assert any("invalid regex" in e for e in errors)

def test_validate_valid_regex_with_inline_flags():
    config = {"commands": [{"command": "x", "ask": {"arg_regex": "(?i)POST"}}]}
    assert validate_config(config) == []


# ── Structural checks ───────────────────────────────────────────────────

def test_validate_nested_subcommands_rejected():
    config = {"commands": [
        {"command": "x", "allow": {"subcommands": [
            {"subcommand": "y", "allow": {"subcommands": ["z"]}}
        ]}}
    ]}
    errors = validate_config(config)
    assert any("nested subcommands" in e for e in errors)

def test_validate_empty_command_string():
    errors = validate_config({"commands": [""]})
    assert any("empty string" in e for e in errors)

def test_validate_empty_command_name():
    errors = validate_config({"commands": [{"command": ""}]})
    assert any("empty string" in e for e in errors)

def test_validate_empty_subcommand_string():
    config = {"commands": [{"command": "x", "allow": {"subcommands": [""]}}]}
    errors = validate_config(config)
    assert any("empty string" in e for e in errors)

def test_validate_empty_subcommand_name():
    config = {"commands": [{"command": "x", "allow": {"subcommands": [{"subcommand": ""}]}}]}
    errors = validate_config(config)
    assert any("empty string" in e for e in errors)

def test_validate_command_instead_of_subcommand():
    """Common typo: 'command' inside subcommands instead of 'subcommand'."""
    config = {"commands": [
        {"command": "git", "allow": {"subcommands": [{"command": "status"}]}}
    ]}
    errors = validate_config(config)
    assert any("did you mean 'subcommand'" in e for e in errors)


# ── Integration: --validate flag ─────────────────────────────────────────

def test_validate_flag_valid_config():
    fd, tmp_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(TEST_CONFIG, f)
    try:
        result = subprocess.run(
            [sys.executable, HOOK, "validate", "--config", tmp_path],
            capture_output=True, text=True,
        )
    finally:
        os.unlink(tmp_path)
    assert result.returncode == 0
    assert "valid" in result.stdout.lower()

def test_validate_flag_invalid_config():
    fd, tmp_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump({"commands": [42]}, f)
    try:
        result = subprocess.run(
            [sys.executable, HOOK, "validate", "--config", tmp_path],
            capture_output=True, text=True,
        )
    finally:
        os.unlink(tmp_path)
    assert result.returncode == 1
    assert "expected string or object" in result.stderr

def test_validate_flag_missing_config():
    result = subprocess.run(
        [sys.executable, HOOK, "validate", "--config", "/tmp/_nonexistent_config_.json"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "not found" in result.stderr.lower()


# ── Validation wired into load_config ────────────────────────────────────

def test_invalid_config_returns_deny():
    """Invalid config should deny with error in reason."""
    fd, tmp_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump({"commands": [42]}, f)

    input_data = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "cwd": "/tmp",
    })
    try:
        result = subprocess.run(
            [sys.executable, HOOK, "hook", "--config", tmp_path],
            input=input_data, capture_output=True, text=True,
        )
    finally:
        os.unlink(tmp_path)
    assert result.returncode == 1
    output = json.loads(result.stdout)
    hook = output["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"


# ── Local config: unit tests ─────────────────────────────────────────────

find_local_configs = _mod.find_local_configs
merge_commands = _mod.merge_commands
merge_allowed_directories = _mod.merge_allowed_directories


def test_find_local_configs_discovers_files(tmp_path):
    """find_local_configs finds .bashgate.json at multiple levels."""
    # Create directory tree: tmp_path/a/b/c
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)

    # Place configs at root and at 'a/b'
    (tmp_path / ".bashgate.json").write_text('{"commands": ["ls"]}')
    (tmp_path / "a" / "b" / ".bashgate.json").write_text('{"commands": ["cat"]}')

    result = find_local_configs(str(deep))
    # Should find both, furthest-ancestor first
    assert len(result) == 2
    assert result[0] == str(tmp_path / ".bashgate.json")
    assert result[1] == str(tmp_path / "a" / "b" / ".bashgate.json")


def test_find_local_configs_no_files(tmp_path):
    """find_local_configs returns empty list when no config files exist."""
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    result = find_local_configs(str(deep))
    # May find files above tmp_path in the real filesystem, but none in tmp_path tree
    for path in result:
        assert not path.startswith(str(tmp_path))


def test_find_local_configs_at_cwd(tmp_path):
    """find_local_configs finds config in cwd itself."""
    (tmp_path / ".bashgate.json").write_text('{"commands": []}')
    result = find_local_configs(str(tmp_path))
    assert any(r == str(tmp_path / ".bashgate.json") for r in result)


def test_merge_commands_string_dedup():
    """Later list overrides earlier list for same string key."""
    a = ["ls", "cat"]
    b = ["cat", "echo"]
    result = merge_commands(a, b)
    # ls from a, cat from b (replaced), echo from b
    assert result == ["ls", "cat", "echo"]


def test_merge_commands_object_dedup():
    """Later list overrides earlier list for same command key."""
    a = [{"command": "sed", "ask": {"flags": ["-i"]}}]
    b = [{"command": "sed", "ask": {"flags": ["-i", "--in-place"]}}]
    result = merge_commands(a, b)
    assert len(result) == 1
    assert result[0] == b[0]


def test_merge_commands_mixed():
    """String and object entries with same command name: object replaces string."""
    a = ["sed"]
    b = [{"command": "sed", "ask": {"flags": ["-i"]}}]
    result = merge_commands(a, b)
    assert len(result) == 1
    assert isinstance(result[0], dict)


def test_merge_commands_union():
    """Non-overlapping entries are all included."""
    a = ["ls", "cat"]
    b = ["echo", "grep"]
    result = merge_commands(a, b)
    assert result == ["ls", "cat", "echo", "grep"]


def test_merge_commands_preserves_order():
    """Entries appear in first-seen order, with replacements in-place."""
    a = ["ls", "cat", "echo"]
    b = ["cat"]  # replaces cat
    result = merge_commands(a, b)
    assert result == ["ls", "cat", "echo"]


def test_merge_commands_three_lists():
    """Three-way merge: each successive list can override."""
    a = ["ls"]
    b = [{"command": "ls", "ask": {"flags": ["-R"]}}]
    c = ["ls"]  # back to simple string
    result = merge_commands(a, b, c)
    assert len(result) == 1
    assert result[0] == "ls"


# ── Local config: integration tests ─────────────────────────────────────

def _run_hook_with_local_config(command, cwd, global_config=None, local_configs=None):
    """Run the hook with a global config file and local .bashgate.json files.

    global_config: dict for global config (default: empty commands)
    local_configs: dict mapping directory paths to config dicts to write as
                   .bashgate.json at those locations
    """
    if global_config is None:
        global_config = {"commands": []}

    # Write global config to a temp file in a location that won't be found
    # by local config discovery
    fd, global_path = tempfile.mkstemp(suffix=".json", dir="/tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(global_config, f)

    # Write local configs
    written_files = []
    if local_configs:
        for dir_path, config_data in local_configs.items():
            config_file = os.path.join(dir_path, ".bashgate.json")
            with open(config_file, "w") as f:
                json.dump(config_data, f)
            written_files.append(config_file)

    input_data = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": cwd,
    })

    try:
        run_env = os.environ.copy()
        run_env["BASHGATE_GLOBAL_CONFIG"] = global_path
        result = subprocess.run(
            [sys.executable, HOOK, "hook"],
            input=input_data,
            capture_output=True,
            text=True,
            env=run_env,
        )
    finally:
        os.unlink(global_path)
        for f in written_files:
            if os.path.exists(f):
                os.unlink(f)

    if result.returncode != 0:
        return ("error", result.returncode)

    if not result.stdout.strip():
        return (None, None)
    output = json.loads(result.stdout)
    hook = output["hookSpecificOutput"]
    return (hook["permissionDecision"], hook["permissionDecisionReason"])


def test_local_config_adds_command(tmp_path):
    """A local .bashgate.json can add commands not in the global config."""
    cwd = str(tmp_path)
    local_config = {"commands": ["curl"]}
    config_file = tmp_path / ".bashgate.json"
    config_file.write_text(json.dumps(local_config))

    try:
        decision, reason = _run_hook_with_local_config("curl http://example.com", cwd)
        assert decision == "allow"
        assert "curl" in reason
    finally:
        if config_file.exists():
            config_file.unlink()


def test_local_config_overrides_global(tmp_path):
    """Local config can override a global command entry with stricter deny rules."""
    cwd = str(tmp_path)
    # Local config adds sed with -i blocked
    local_config = {"commands": [{"command": "sed", "ask": {"flags": ["-i"]}}]}
    config_file = tmp_path / ".bashgate.json"
    config_file.write_text(json.dumps(local_config))

    try:
        # sed -i should be blocked by local config's deny rule
        decision, reason = _run_hook_with_local_config("sed -i 's/a/b/' file.txt", cwd)
        assert decision == "ask"
        assert "-i" in reason
    finally:
        if config_file.exists():
            config_file.unlink()


def test_local_config_multi_level(tmp_path):
    """Configs at multiple directory levels are merged with nearest having highest precedence."""
    # grandparent has curl allowed
    grandparent = tmp_path
    parent = tmp_path / "project"
    child = parent / "src"
    child.mkdir(parents=True)

    gp_config = {"commands": ["curl", "wget"]}
    (grandparent / ".bashgate.json").write_text(json.dumps(gp_config))

    # parent overrides curl with deny rules
    p_config = {"commands": [{"command": "curl", "ask": {"flags": ["--upload-file"]}}]}
    (parent / ".bashgate.json").write_text(json.dumps(p_config))

    try:
        cwd = str(child)
        # curl without --upload-file should be allowed (structured entry from parent)
        decision, _ = _run_hook_with_local_config("curl http://example.com", cwd)
        assert decision == "allow"

        # curl --upload-file should be blocked by parent's deny
        decision, reason = _run_hook_with_local_config("curl --upload-file data.txt http://example.com", cwd)
        assert decision == "ask"
        assert "--upload-file" in reason

        # wget should still be allowed from grandparent
        decision, _ = _run_hook_with_local_config("wget http://example.com", cwd)
        assert decision == "allow"
    finally:
        for cfg in [grandparent / ".bashgate.json", parent / ".bashgate.json"]:
            if cfg.exists():
                cfg.unlink()


def test_explicit_config_skips_local_discovery(tmp_path):
    """--config flag should skip local config discovery entirely."""
    cwd = str(tmp_path)
    # Put a local config that would allow 'curl'
    local_config = {"commands": ["curl"]}
    config_file = tmp_path / ".bashgate.json"
    config_file.write_text(json.dumps(local_config))

    # Explicit config with only 'ls'
    fd, explicit_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump({"commands": ["ls"]}, f)

    input_data = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "curl http://example.com"},
        "cwd": cwd,
    })

    try:
        result = subprocess.run(
            [sys.executable, HOOK, "hook", "--config", explicit_path],
            input=input_data,
            capture_output=True,
            text=True,
        )
        # curl should NOT be allowed when using explicit config
        if result.stdout.strip():
            output = json.loads(result.stdout)
            hook = output["hookSpecificOutput"]
            assert hook["permissionDecision"] != "allow"
        else:
            # Fall through (not in allowlist) is also acceptable
            pass
    finally:
        config_file.unlink()
        os.unlink(explicit_path)


# ── allowed_directories ──────────────────────────────────────────────────

def test_allowed_directory_permits_path():
    """Path in an allowed directory should be permitted."""
    config = {"commands": ["cat"], "allowed_directories": ["/etc"]}
    decision, _ = run_hook("cat /etc/passwd", config=config, cwd="/tmp")
    assert decision == "allow"

def test_allowed_directory_subdirectory():
    """Path in a subdirectory of an allowed directory should be permitted."""
    config = {"commands": ["cat"], "allowed_directories": ["/usr"]}
    decision, _ = run_hook("cat /usr/local/bin/foo", config=config, cwd="/tmp")
    assert decision == "allow"

def test_allowed_directory_still_blocks_other_paths():
    """Paths outside both cwd and allowed directories should still be blocked."""
    config = {"commands": ["cat"], "allowed_directories": ["/usr"]}
    decision, reason = run_hook("cat /etc/passwd", config=config, cwd="/tmp")
    assert decision == "ask"
    assert "/etc/passwd" in reason

def test_allowed_directory_tilde_expansion():
    """allowed_directories with ~ should be expanded."""
    home = os.path.expanduser("~")
    config = {"commands": ["cat"], "allowed_directories": ["~/.config"]}
    decision, _ = run_hook(f"cat {home}/.config/some.conf", config=config, cwd="/tmp")
    assert decision == "allow"

def test_allowed_directory_exact_match():
    """Path that is exactly the allowed directory (not a child) should be permitted."""
    config = {"commands": ["cat"], "allowed_directories": ["/etc"]}
    decision, _ = run_hook("cat /etc", config=config, cwd="/tmp")
    assert decision == "allow"

def test_allowed_directory_with_structured_command():
    """allowed_directories should work with structured (subcommand) entries too."""
    config = {
        "commands": [
            {
                "command": "git",
                "flags_with_args": ["-C"],
                "allow": {"subcommands": ["log"]}
            }
        ],
        "allowed_directories": ["/opt/repos"]
    }
    decision, _ = run_hook("git -C /opt/repos/myrepo log", config=config, cwd="/tmp")
    assert decision == "allow"

def test_allowed_directory_with_prefix_command():
    """allowed_directories should work with prefix-matched (string) entries."""
    config = {"commands": ["ls"], "allowed_directories": ["/var/log"]}
    decision, _ = run_hook("ls /var/log/syslog", config=config, cwd="/tmp")
    assert decision == "allow"

def test_allowed_directory_dotdot_resolving_into_allowed():
    """A .. path that resolves into an allowed directory should be permitted."""
    config = {"commands": ["cat"], "allowed_directories": ["/etc"]}
    decision, _ = run_hook("cat /etc/subdir/../passwd", config=config, cwd="/tmp")
    assert decision == "allow"

def test_allowed_directory_dotdot_resolving_outside():
    """A .. path that resolves outside both cwd and allowed dirs should be blocked."""
    config = {"commands": ["cat"], "allowed_directories": ["/etc"]}
    decision, _ = run_hook("cat /etc/../var/secret", config=config, cwd="/tmp")
    assert decision == "ask"


# ── allowed_directories: relative paths ──────────────────────────────────

load_config = _mod.load_config

def test_allowed_directory_dot_resolved_relative_to_config_file(tmp_path):
    """allowed_directories with '.' prefix should resolve relative to config file location."""
    config_dir = tmp_path / "project"
    config_dir.mkdir()
    target_dir = config_dir / "vendor" / "cache"
    target_dir.mkdir(parents=True)

    config_file = config_dir / "config.json"
    config_file.write_text(json.dumps({
        "commands": ["cat"],
        "allowed_directories": ["./vendor/cache"]
    }))

    _, allowed_dirs, _opts = load_config(str(config_file))
    assert len(allowed_dirs) == 1
    assert allowed_dirs[0] == os.path.realpath(str(target_dir))

def test_allowed_directory_dot_only(tmp_path):
    """allowed_directories with just '.' should resolve to config file's directory."""
    config_dir = tmp_path / "project"
    config_dir.mkdir()

    config_file = config_dir / "config.json"
    config_file.write_text(json.dumps({
        "commands": ["cat"],
        "allowed_directories": ["."]
    }))

    _, allowed_dirs, _opts = load_config(str(config_file))
    assert len(allowed_dirs) == 1
    assert allowed_dirs[0] == os.path.realpath(str(config_dir))

def test_allowed_directory_dotdot_relative(tmp_path):
    """allowed_directories with '..' should resolve relative to config file location."""
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)

    config_file = child / "config.json"
    config_file.write_text(json.dumps({
        "commands": ["cat"],
        "allowed_directories": ["../sibling"]
    }))

    _, allowed_dirs, _opts = load_config(str(config_file))
    assert len(allowed_dirs) == 1
    assert allowed_dirs[0] == os.path.realpath(str(parent / "sibling"))

def test_allowed_directory_absolute_not_affected(tmp_path):
    """Absolute paths in allowed_directories should not be modified."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "commands": ["cat"],
        "allowed_directories": ["/usr/local"]
    }))

    _, allowed_dirs, _opts = load_config(str(config_file))
    assert allowed_dirs == ["/usr/local"]

def test_allowed_directory_tilde_not_affected(tmp_path):
    """Tilde paths should not be modified (they don't start with '.')."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "commands": ["cat"],
        "allowed_directories": ["~/.config"]
    }))

    _, allowed_dirs, _opts = load_config(str(config_file))
    assert allowed_dirs == ["~/.config"]

def test_allowed_directory_relative_integration(tmp_path):
    """Integration test: relative allowed_directories permits the right path."""
    project = tmp_path / "project"
    project.mkdir()
    vendor = project / "vendor"
    vendor.mkdir()

    config = {"commands": ["cat"], "allowed_directories": ["./vendor"]}
    config_file = project / "test-config.json"
    config_file.write_text(json.dumps(config))

    input_data = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": f"cat {vendor}/somefile"},
        "cwd": "/tmp",
    })

    result = subprocess.run(
        [sys.executable, HOOK, "hook", "--config", str(config_file)],
        input=input_data,
        capture_output=True,
        text=True,
    )

    output = json.loads(result.stdout)
    hook = output["hookSpecificOutput"]
    assert hook["permissionDecision"] == "allow"

def test_allowed_directory_relative_blocks_outside(tmp_path):
    """Integration test: relative allowed_directories still blocks other paths."""
    project = tmp_path / "project"
    project.mkdir()

    config = {"commands": ["cat"], "allowed_directories": ["./vendor"]}
    config_file = project / "test-config.json"
    config_file.write_text(json.dumps(config))

    input_data = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "cat /etc/passwd"},
        "cwd": "/tmp",
    })

    result = subprocess.run(
        [sys.executable, HOOK, "hook", "--config", str(config_file)],
        input=input_data,
        capture_output=True,
        text=True,
    )

    output = json.loads(result.stdout)
    hook = output["hookSpecificOutput"]
    assert hook["permissionDecision"] == "ask"
    assert "/etc/passwd" in hook["permissionDecisionReason"]


# ── allowed_directories: merge ───────────────────────────────────────────

def test_merge_allowed_directories_union():
    """Merging unions all directories, deduplicating."""
    result = merge_allowed_directories(["/a", "/b"], ["/b", "/c"])
    assert result == ["/a", "/b", "/c"]

def test_merge_allowed_directories_empty():
    """Merging empty lists produces empty list."""
    result = merge_allowed_directories([], [])
    assert result == []

def test_merge_allowed_directories_single():
    """Single list passes through."""
    result = merge_allowed_directories(["/a", "/b"])
    assert result == ["/a", "/b"]

def test_merge_allowed_directories_preserves_order():
    """First-seen order is preserved."""
    result = merge_allowed_directories(["/c", "/a"], ["/b", "/a"])
    assert result == ["/c", "/a", "/b"]


# ── allowed_directories: validation ──────────────────────────────────────

def test_validate_allowed_directories_valid():
    """Valid allowed_directories passes validation."""
    assert validate_config({"commands": [], "allowed_directories": ["/etc", "~/bin"]}) == []

def test_validate_allowed_directories_wrong_type():
    """allowed_directories must be a list."""
    errors = validate_config({"commands": [], "allowed_directories": "/etc"})
    assert any("expected array" in e for e in errors)

def test_validate_allowed_directories_non_string_item():
    """allowed_directories items must be strings."""
    errors = validate_config({"commands": [], "allowed_directories": [42]})
    assert any("expected string" in e for e in errors)

def test_validate_allowed_directories_empty_string():
    """allowed_directories items must not be empty strings."""
    errors = validate_config({"commands": [], "allowed_directories": [""]})
    assert any("empty string" in e for e in errors)

def test_validate_unknown_key_still_caught_with_allowed_directories():
    """Unknown top-level keys should still be caught."""
    errors = validate_config({"commands": [], "allowed_directories": [], "extra": True})
    assert any("unknown key 'extra'" in e for e in errors)


# ── git push ─────────────────────────────────────────────────────────────

def test_git_push_basic():
    assert run_hook("git push") == ("allow", "Allowed command: git push")

def test_git_push_origin_main():
    assert run_hook("git push origin main") == ("allow", "Allowed command: git push")

def test_git_push_set_upstream():
    assert run_hook("git push -u origin feature-branch") == ("allow", "Allowed command: git push")

def test_git_push_long_set_upstream():
    assert run_hook("git push --set-upstream origin feature-branch") == ("allow", "Allowed command: git push")

def test_git_push_force_blocked():
    decision, reason = run_hook("git push --force")
    assert decision == "ask"
    assert "--force" in reason

def test_git_push_force_short_blocked():
    decision, reason = run_hook("git push -f origin main")
    assert decision == "ask"
    assert "-f" in reason

def test_git_push_force_with_lease_blocked():
    decision, reason = run_hook("git push --force-with-lease")
    assert decision == "ask"
    assert "--force-with-lease" in reason

def test_git_push_force_if_includes_blocked():
    decision, reason = run_hook("git push --force-if-includes")
    assert decision == "ask"
    assert "--force-if-includes" in reason

def test_git_push_delete_blocked():
    decision, reason = run_hook("git push --delete origin feature")
    assert decision == "ask"
    assert "--delete" in reason

def test_git_push_delete_short_blocked():
    decision, reason = run_hook("git push -d origin feature")
    assert decision == "ask"
    assert "-d" in reason

def test_git_push_mirror_blocked():
    decision, reason = run_hook("git push --mirror")
    assert decision == "ask"
    assert "--mirror" in reason

def test_git_push_all_blocked():
    decision, reason = run_hook("git push --all")
    assert decision == "ask"
    assert "--all" in reason

def test_git_push_prune_blocked():
    decision, reason = run_hook("git push --prune")
    assert decision == "ask"
    assert "--prune" in reason

def test_git_push_no_verify_blocked():
    decision, reason = run_hook("git push --no-verify")
    assert decision == "ask"
    assert "--no-verify" in reason

def test_git_push_colon_refspec_blocked():
    """Colon-prefixed refspec (:branch) is git's delete syntax and should be blocked."""
    decision, reason = run_hook("git push origin :branch-name")
    assert decision == "ask"
    assert ":branch-name" in reason

def test_git_push_normal_refspec_allowed():
    """Normal src:dst refspec (local:remote) should be allowed."""
    assert run_hook("git push origin local:remote") == ("allow", "Allowed command: git push")

def test_git_push_compound_allowed():
    """git push in a compound command should be allowed."""
    decision, _ = run_hook("git add . && git commit -m 'msg' && git push")
    assert decision == "allow"


def _with_sandbox_settings(cwd, enabled):
    """Create .claude/settings.local.json with sandbox settings in cwd."""
    claude_dir = os.path.join(cwd, ".claude")
    os.makedirs(claude_dir, exist_ok=True)
    settings_path = os.path.join(claude_dir, "settings.local.json")
    with open(settings_path, "w") as f:
        json.dump({"sandbox": {"enabled": enabled}}, f)


def test_disable_inside_sandbox_falls_through():
    """With disable_inside_sandbox=true and sandbox enabled, hook falls through."""
    config = {"commands": ["echo"], "disable_inside_sandbox": True}
    with tempfile.TemporaryDirectory() as tmpdir:
        _with_sandbox_settings(tmpdir, True)
        assert run_hook("echo hello", cwd=tmpdir, config=config) == (None, None)

def test_disable_inside_sandbox_false_still_filters():
    """With disable_inside_sandbox=false and sandbox enabled, hook still filters."""
    config = {"commands": ["echo"], "disable_inside_sandbox": False}
    with tempfile.TemporaryDirectory() as tmpdir:
        _with_sandbox_settings(tmpdir, True)
        assert run_hook("echo hello", cwd=tmpdir, config=config) == ("allow", "Allowed command: echo")

def test_disable_inside_sandbox_without_sandbox_still_filters():
    """With disable_inside_sandbox=true but sandbox not enabled, hook still filters."""
    config = {"commands": ["echo"], "disable_inside_sandbox": True}
    with tempfile.TemporaryDirectory() as tmpdir:
        assert run_hook("echo hello", cwd=tmpdir, config=config) == ("allow", "Allowed command: echo")

def test_disable_inside_sandbox_default_false():
    """Without disable_inside_sandbox key, sandbox doesn't affect behavior."""
    config = {"commands": ["echo"]}
    with tempfile.TemporaryDirectory() as tmpdir:
        _with_sandbox_settings(tmpdir, True)
        assert run_hook("echo hello", cwd=tmpdir, config=config) == ("allow", "Allowed command: echo")

def test_validate_disable_inside_sandbox_wrong_type():
    errors = _mod.validate_config({"commands": [], "disable_inside_sandbox": "yes"})
    assert any("disable_inside_sandbox" in e for e in errors)

def test_enabled_false_falls_through():
    """With enabled=false, hook falls through for all commands."""
    config = {"commands": ["echo"], "enabled": False}
    assert run_hook("echo hello", config=config) == (None, None)

def test_enabled_true_still_filters():
    """With enabled=true (explicit), hook still filters normally."""
    config = {"commands": ["echo"], "enabled": True}
    assert run_hook("echo hello", config=config) == ("allow", "Allowed command: echo")

def test_enabled_default_true():
    """Without enabled key, hook filters normally."""
    config = {"commands": ["echo"]}
    assert run_hook("echo hello", config=config) == ("allow", "Allowed command: echo")

def test_enabled_false_even_dangerous_falls_through():
    """With enabled=false, even dangerous commands fall through (no opinion)."""
    config = {"commands": ["echo"], "enabled": False}
    assert run_hook("echo $HOME", config=config) == (None, None)

def test_validate_enabled_wrong_type():
    errors = _mod.validate_config({"commands": [], "enabled": "yes"})
    assert any("enabled" in e for e in errors)


# ── deny config (hard block) ─────────────────────────────────────────────

def test_deny_unconditional():
    """Command with deny and no flags/arg_regex is unconditionally denied."""
    config = {"commands": [{"command": "find", "deny": {"message": "use `fd` instead of `find`"}}]}
    decision, reason = run_hook("find . -name '*.py'", config=config)
    assert decision == "deny"
    assert "use `fd` instead of `find`" in reason

def test_deny_unconditional_no_message():
    """Unconditional deny without message uses default text."""
    config = {"commands": [{"command": "rm", "deny": {}}]}
    decision, reason = run_hook("rm foo", config=config)
    assert decision == "deny"
    assert "blocked" in reason.lower()

def test_deny_with_flags():
    """Deny with flags only triggers on matching flags."""
    config = {"commands": [{"command": "git", "allow": {"subcommands": ["push"]}, "deny": {"flags": ["--force"]}}]}
    # Without the flag: allowed
    decision, _ = run_hook("git push", config=config)
    assert decision == "allow"
    # With the flag: denied
    decision, reason = run_hook("git push --force", config=config)
    assert decision == "deny"
    assert "--force" in reason

def test_deny_with_message_and_flags():
    """Deny with flags and a custom message uses the message text."""
    config = {"commands": [{"command": "rm", "deny": {"flags": ["-rf"], "message": "dangerous rm"}}]}
    decision, reason = run_hook("rm -rf /", config=config)
    assert decision == "deny"
    assert "dangerous rm" in reason

def test_deny_on_subcommand():
    """Deny on a subcommand entry returns deny decision."""
    config = {"commands": [{
        "command": "git",
        "allow": {"subcommands": [
            {"subcommand": "reset", "deny": {"message": "git reset is dangerous"}}
        ]}
    }]}
    decision, reason = run_hook("git reset", config=config)
    assert decision == "deny"
    assert "git reset is dangerous" in reason

def test_ask_still_works():
    """Ask config still returns ask decision (not deny)."""
    config = {"commands": [{"command": "rm", "ask": {"flags": ["-rf"]}}]}
    decision, reason = run_hook("rm -rf /", config=config)
    assert decision == "ask"
    assert "-rf" in reason

def test_deny_checked_before_ask():
    """When both deny and ask are configured, deny is checked first."""
    config = {"commands": [{"command": "rm", "deny": {"flags": ["-rf"]}, "ask": {"flags": ["-r"]}}]}
    # -rf matches deny
    decision, _ = run_hook("rm -rf foo", config=config)
    assert decision == "deny"
    # -r matches ask (not deny)
    decision, _ = run_hook("rm -r foo", config=config)
    assert decision == "ask"

def test_deny_in_compound_command():
    """Deny in a compound command propagates correctly."""
    config = {"commands": ["echo", {"command": "find", "deny": {"message": "use fd"}}]}
    decision, reason = run_hook("echo hi && find . -name '*.py'", config=config)
    assert decision == "deny"
    assert "use fd" in reason

def test_deny_prefix_entry():
    """Deny works on prefix (non-structured) entries too."""
    config = {"commands": [{"command": "find", "deny": {"message": "use fd"}}]}
    decision, reason = run_hook("find .", config=config)
    assert decision == "deny"
    assert "use fd" in reason

def test_validate_deny_message_not_string():
    """Validation catches non-string deny.message."""
    errors = _mod.validate_config({"commands": [{"command": "x", "deny": {"message": 42}}]})
    assert any("message" in e and "expected string" in e for e in errors)

def test_validate_deny_message_empty():
    """Validation catches empty deny.message."""
    errors = _mod.validate_config({"commands": [{"command": "x", "deny": {"message": ""}}]})
    assert any("empty string" in e for e in errors)

def test_validate_ask_message():
    """Ask with message is also valid."""
    errors = _mod.validate_config({"commands": [{"command": "x", "ask": {"message": "please approve"}}]})
    assert errors == []

def test_ask_with_message():
    """Ask with custom message uses that message."""
    config = {"commands": [{"command": "rm", "ask": {"flags": ["-rf"], "message": "please confirm rm -rf"}}]}
    decision, reason = run_hook("rm -rf foo", config=config)
    assert decision == "ask"
    assert "please confirm rm -rf" in reason


# ── Install command tests ─────────────────────────────────────────────────

def test_install_fresh_settings():
    """Install into empty settings file creates the hook."""
    with tempfile.TemporaryDirectory() as tmpdir:
        settings_path = os.path.join(tmpdir, "settings.json")
        with open(settings_path, "w") as f:
            json.dump({}, f)
        result = subprocess.run(
            [sys.executable, HOOK, "install"],
            capture_output=True, text=True,
            env={**os.environ, "HOME": tmpdir, "BASHGATE_SETTINGS_PATH": settings_path},
        )
        assert result.returncode == 0
        with open(settings_path) as f:
            settings = json.load(f)
        pre_tool_use = settings["hooks"]["PreToolUse"]
        bash_entries = [e for e in pre_tool_use if e["matcher"] == "Bash"]
        assert len(bash_entries) == 1
        assert "bashgate" in bash_entries[0]["hooks"][0]["command"]


def test_install_updates_existing_hook():
    """Install updates an existing bashgate hook command."""
    with tempfile.TemporaryDirectory() as tmpdir:
        settings_path = os.path.join(tmpdir, "settings.json")
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 /old/path/bashgate.py"}],
                    }
                ]
            }
        }
        with open(settings_path, "w") as f:
            json.dump(settings, f)
        result = subprocess.run(
            [sys.executable, HOOK, "install"],
            capture_output=True, text=True,
            env={**os.environ, "HOME": tmpdir, "BASHGATE_SETTINGS_PATH": settings_path},
        )
        assert result.returncode == 0
        assert "Updated" in result.stdout
        with open(settings_path) as f:
            updated = json.load(f)
        hook_cmd = updated["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert "bashgate" in hook_cmd
        assert "/old/path/" not in hook_cmd


def test_install_preserves_other_hooks():
    """Install doesn't remove other PreToolUse hooks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        settings_path = os.path.join(tmpdir, "settings.json")
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "echo hi"}]},
                ]
            }
        }
        with open(settings_path, "w") as f:
            json.dump(settings, f)
        result = subprocess.run(
            [sys.executable, HOOK, "install"],
            capture_output=True, text=True,
            env={**os.environ, "HOME": tmpdir, "BASHGATE_SETTINGS_PATH": settings_path},
        )
        assert result.returncode == 0
        with open(settings_path) as f:
            updated = json.load(f)
        pre_tool_use = updated["hooks"]["PreToolUse"]
        assert len(pre_tool_use) == 2
        assert pre_tool_use[0]["matcher"] == ""


def test_install_no_settings_file():
    """Install creates settings.json if it doesn't exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        settings_path = os.path.join(tmpdir, "subdir", "settings.json")
        result = subprocess.run(
            [sys.executable, HOOK, "install"],
            capture_output=True, text=True,
            env={**os.environ, "HOME": tmpdir, "BASHGATE_SETTINGS_PATH": settings_path},
        )
        assert result.returncode == 0
        assert os.path.isfile(settings_path)
        with open(settings_path) as f:
            settings = json.load(f)
        assert "bashgate" in settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]


# ── ignore_local_configs option ────────────────────────────────────────

def test_ignore_local_configs_skips_local(tmp_path):
    """Global config with ignore_local_configs=true skips local .bashgate.json files."""
    cwd = str(tmp_path)
    local_config = {"commands": ["curl"]}
    config_file = tmp_path / ".bashgate.json"
    config_file.write_text(json.dumps(local_config))
    global_config = {"commands": ["echo"], "ignore_local_configs": True}
    try:
        decision, _ = _run_hook_with_local_config("curl http://example.com", cwd, global_config=global_config)
        assert decision is None  # curl not in global, local skipped => fallthrough
    finally:
        if config_file.exists():
            config_file.unlink()

def test_ignore_local_configs_false_still_merges(tmp_path):
    """Global config with ignore_local_configs=false still merges local configs."""
    cwd = str(tmp_path)
    local_config = {"commands": ["curl"]}
    config_file = tmp_path / ".bashgate.json"
    config_file.write_text(json.dumps(local_config))
    global_config = {"commands": ["echo"], "ignore_local_configs": False}
    try:
        decision, reason = _run_hook_with_local_config("curl http://example.com", cwd, global_config=global_config)
        assert decision == "allow"
        assert "curl" in reason
    finally:
        if config_file.exists():
            config_file.unlink()

def test_validate_ignore_local_configs_wrong_type():
    errors = _mod.validate_config({"commands": [], "ignore_local_configs": "yes"})
    assert any("ignore_local_configs" in e for e in errors)


# ── local config enabled: false ───────────────────────────────────────

def test_local_config_enabled_false_disables_hook(tmp_path):
    """A local config with enabled=false disables bashgate for that project."""
    cwd = str(tmp_path)
    local_config = {"enabled": False}
    config_file = tmp_path / ".bashgate.json"
    config_file.write_text(json.dumps(local_config))
    global_config = {"commands": ["echo"]}
    try:
        decision, _ = _run_hook_with_local_config("echo hello", cwd, global_config=global_config)
        assert decision is None  # falls through, hook disabled
    finally:
        if config_file.exists():
            config_file.unlink()

def test_ignore_local_configs_prevents_local_disable(tmp_path):
    """ignore_local_configs=true prevents a local config from disabling the hook."""
    cwd = str(tmp_path)
    local_config = {"enabled": False}
    config_file = tmp_path / ".bashgate.json"
    config_file.write_text(json.dumps(local_config))
    global_config = {"commands": ["echo"], "ignore_local_configs": True}
    try:
        decision, _ = _run_hook_with_local_config("echo hello", cwd, global_config=global_config)
        assert decision == "allow"  # local config ignored, global allows echo
    finally:
        if config_file.exists():
            config_file.unlink()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
