#!/usr/bin/env python3
"""MI50 Guardian - checks commands an AI agent wants to run before they run.

Standard library only (works on Ubuntu 22.04's Python 3.10).

Modes:
  guardian.py check "<command>"   exit 0 = allow, 1 = ask, 2 = deny
  guardian.py hook                Claude Code PreToolUse hook (JSON on stdin)
  guardian.py shell -c "<cmd>"    drop-in $SHELL for agents: checks, then runs bash
  guardian.py pause | resume      kill switch: while paused every command is denied
  guardian.py log [N]             show the last N decisions (default 20)

Every decision is appended to a JSONL audit log.
"""
import json
import os
import re
import shlex
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES_FILE = Path(os.environ.get("GUARDIAN_RULES", HERE / "rules.json"))
STATE_DIR = Path(os.environ.get("GUARDIAN_STATE",
                                Path.home() / ".local/state/mi50-guardian"))
LOG_FILE = STATE_DIR / "audit.jsonl"
HISTORY_FILE = STATE_DIR / "history.json"
PAUSE_FILE = STATE_DIR / "PAUSED"
REAL_SHELL = os.environ.get("GUARDIAN_REAL_SHELL", "/bin/bash")

ALLOW, ASK, DENY = "allow", "ask", "deny"
RANK = {ALLOW: 0, ASK: 1, DENY: 2}

# Things that make a command impossible to judge piece by piece.
OPAQUE = re.compile(r"\$\(|`|\beval\b|\bbase64\s+(-d|--decode)\b|\bsource\b|^\.\s")
HARMLESS_DEVICES = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}
REDIRECT = re.compile(r"\d*>>?\|?\s*([^\s&;|<>]+)")
WRITES_LAST_ARG = {"cp", "mv", "ln", "install"}
WRITES_ALL_ARGS = {"tee", "rm", "rmdir", "chmod", "chown", "chgrp", "truncate", "touch", "mkdir", "shred"}


def load_rules(path=RULES_FILE):
    with open(path) as f:
        rules = json.load(f)
    for key in ("deny", "ask", "allow"):
        rules[key] = [(re.compile(p, re.IGNORECASE), why) for p, why in rules.get(key, [])]
    return rules


def split_command(cmd):
    """Split on ; && || | and newlines (good enough to judge each piece)."""
    parts = re.split(r"\|\||&&|[;|\n]|(?<![<>])&(?!>)", cmd)
    return [p.strip() for p in parts if p.strip()]


def _first(patterns, text):
    for rx, why in patterns:
        if rx.search(text):
            return why
    return None


def write_targets(piece):
    """Paths a single command would write to (redirects + args of writing verbs)."""
    targets = [t for t in REDIRECT.findall(piece) if not t.isdigit()]
    try:
        tokens = shlex.split(REDIRECT.sub(" ", piece))
    except ValueError:
        tokens = REDIRECT.sub(" ", piece).split()
    while tokens and re.match(r"^\w+=", tokens[0]):  # FOO=bar cmd ...
        tokens.pop(0)
    if not tokens:
        return targets
    verb, args = os.path.basename(tokens[0]), tokens[1:]
    paths = [a for a in args if not a.startswith("-")]
    if verb in WRITES_LAST_ARG and paths:
        targets.append(paths[-1])
    elif verb in WRITES_ALL_ARGS or (verb == "sed" and any(a.startswith("-i") for a in args)):
        targets += paths
    elif verb == "dd":
        targets += [a[3:] for a in args if a.startswith("of=")]
    return targets


def touches_protected_path(cmd, protected):
    home = str(Path.home())
    for piece in split_command(cmd):
        for tok in write_targets(piece):
            if tok in HARMLESS_DEVICES:
                continue
            expanded = tok.replace("$HOME", home)
            if expanded.startswith("~"):
                expanded = home + expanded[1:]
            for p in protected:
                p_exp = home + p[1:] if p.startswith("~") else p
                if expanded == p_exp or expanded.startswith(p_exp.rstrip("/") + "/"):
                    return f"writes to protected path {p}"
    return None


def classify(cmd, rules):
    """Static rule check. Returns (decision, reason); decision may be None = unknown."""
    if PAUSE_FILE.exists():
        return DENY, "guardian is paused (kill switch on)"

    # Deny rules look at the whole string too, so they still catch things
    # hidden inside quotes, subshells or `python -c "..."`.
    why = _first(rules["deny"], cmd)
    if why:
        return DENY, why
    why = touches_protected_path(cmd, rules.get("protected_paths", []))
    if why:
        return DENY, why

    pieces = split_command(cmd)
    worst, reasons = ALLOW, []
    for piece in pieces:
        why = _first(rules["deny"], piece)
        if why:
            return DENY, why
        why = _first(rules["ask"], piece)
        if why:
            worst = ASK if RANK[ASK] > RANK[worst] else worst
            reasons.append(why)
            continue
        if _first(rules["allow"], piece) is None:
            return None, f"no rule matches: {piece[:80]}"
    if worst == ALLOW and OPAQUE.search(cmd):
        return None, "uses eval/subshell/source - can't verify statically"
    if worst == ASK:
        return ASK, "; ".join(dict.fromkeys(reasons))
    return ALLOW, "matches allow rules"


def loop_check(cmd, rules, now=None, record=True):
    """Catch an agent that is stuck repeating itself or running wild."""
    cfg = rules.get("loop_guard") or {}
    if not cfg:
        return None
    now = now or time.time()
    try:
        history = json.loads(HISTORY_FILE.read_text())
    except (OSError, ValueError):
        history = []
    window = cfg.get("same_command_window_seconds", 120)
    history = [h for h in history if now - h["t"] < max(window, 60)]
    same = sum(1 for h in history if h["c"] == cmd and now - h["t"] < window)
    last_minute = sum(1 for h in history if now - h["t"] < 60)
    if record:
        history.append({"t": now, "c": cmd})
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        HISTORY_FILE.write_text(json.dumps(history[-500:]))
    if same >= cfg.get("same_command_max", 5):
        return f"agent looks stuck: same command {same + 1}x in {window}s"
    if last_minute >= cfg.get("max_commands_per_minute", 60):
        return f"agent running too fast: {last_minute + 1} commands in 60s"
    return None


def llm_review(cmd, rules):
    """Ask a local model (e.g. llama.cpp server on the MI50) for a second opinion."""
    cfg = rules.get("llm_review") or {}
    if not cfg.get("enabled"):
        return None, None
    prompt = (
        "You are a security guard for a Linux GPU server. An autonomous coding agent "
        "wants to run the shell command below. Reply with exactly one line: "
        "'ALLOW: <reason>' if it is clearly harmless for a dev workspace, "
        "'DENY: <reason>' if it could damage the system, leak secrets, or escalate "
        "privileges, or 'ASK: <reason>' if a human should decide.\n\nCommand:\n" + cmd)
    body = json.dumps({
        "model": cfg.get("model", "local"),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 80,
    }).encode()
    headers = {"Content-Type": "application/json"}
    key = os.environ.get(cfg.get("api_key_env", ""), "")
    if key:
        headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(cfg["endpoint"].rstrip("/") + "/chat/completions",
                                 data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=cfg.get("timeout_seconds", 20)) as r:
            text = json.load(r)["choices"][0]["message"]["content"].strip()
    except Exception as e:  # model down -> fall back to static policy
        return None, f"llm review unavailable ({e.__class__.__name__})"
    m = re.search(r"\b(ALLOW|DENY|ASK)\b\s*:?\s*(.*)", text, re.IGNORECASE)
    if not m:
        return ASK, "llm gave unclear answer"
    return m.group(1).lower(), "llm: " + m.group(2)[:200]


def decide(cmd, rules=None, record=True):
    rules = rules or load_rules()
    decision, reason = classify(cmd, rules)
    if decision != DENY:
        looping = loop_check(cmd, rules, record=record)
        if looping:
            decision, reason = DENY, looping
    if decision is None:
        llm_decision, llm_reason = llm_review(cmd, rules)
        if llm_decision:
            decision, reason = llm_decision, llm_reason
        else:
            decision = rules.get("unknown_action", ASK)
            if llm_reason:
                reason += "; " + llm_reason
    return decision, reason


def audit(source, cmd, decision, reason):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps({
                "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "source": source,
                "agent": os.environ.get("PAPERCLIP_AGENT_ID") or os.environ.get("USER"),
                "cwd": os.getcwd(),
                "decision": decision,
                "reason": reason,
                "command": cmd,
            }) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- modes

def mode_check(args):
    cmd = " ".join(args)
    decision, reason = decide(cmd)
    audit("check", cmd, decision, reason)
    print(f"{decision.upper()}: {reason}")
    return RANK[decision]


def mode_hook():
    """Claude Code PreToolUse hook. Configure with matcher "Bash|Write|Edit|MultiEdit"."""
    event = json.load(sys.stdin)
    tool = event.get("tool_name", "")
    tin = event.get("tool_input", {}) or {}
    rules = load_rules()
    if tool == "Bash":
        cmd = tin.get("command", "")
        decision, reason = decide(cmd, rules)
    else:
        path = tin.get("file_path") or tin.get("notebook_path") or ""
        cmd = f"{tool} {path}"
        why = touches_protected_path(f"> {path}", rules.get("protected_paths", []))
        if PAUSE_FILE.exists():
            decision, reason = DENY, "guardian is paused (kill switch on)"
        else:
            decision, reason = (DENY, why) if why else (ALLOW, "file edit outside protected paths")
    audit("claude-hook", cmd, decision, reason)
    if decision == ALLOW:
        return 0  # no opinion: let Claude Code's normal permissions apply
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": f"MI50 Guardian: {reason}",
    }}))
    return 0


def mode_shell(args):
    """Used as SHELL for agents that run commands via `$SHELL -c "..."`."""
    i = next((n for n, a in enumerate(args) if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", a)), None)
    if i is None:
        if sys.stdin.isatty():  # a human opening a shell: let them through
            os.execv(REAL_SHELL, [REAL_SHELL] + args)
        sys.stderr.write("MI50 Guardian: non-interactive shell without -c refused\n")
        return 126
    cmd = args[i + 1] if i + 1 < len(args) else ""
    rules = load_rules()
    decision, reason = decide(cmd, rules)
    if decision == ASK:
        if sys.stdin.isatty() and sys.stderr.isatty():
            sys.stderr.write(f"MI50 Guardian wants approval ({reason}):\n  {cmd}\nRun it? [y/N] ")
            sys.stderr.flush()
            ok = sys.stdin.readline().strip().lower() in ("y", "yes")
            decision, reason = (ALLOW, "approved by human") if ok else (DENY, "rejected by human")
        else:
            decision = rules.get("ask_when_unattended", DENY)
            reason += " (no human present)"
    audit("shell", cmd, decision, reason)
    if decision != ALLOW:
        sys.stderr.write(f"MI50 Guardian blocked this command - {reason}\n"
                         "Do not retry it in another form; ask the operator instead.\n")
        return 126
    os.execv(REAL_SHELL, [REAL_SHELL] + args)


def mode_log(args):
    n = int(args[0]) if args else 20
    try:
        lines = LOG_FILE.read_text().splitlines()[-n:]
    except OSError:
        print("no log yet")
        return 0
    for line in lines:
        e = json.loads(line)
        print(f"{e['time']}  {e['decision'].upper():5}  {e['command'][:70]:70}  {e['reason']}")
    return 0


def main(argv):
    if Path(sys.argv[0]).name == "guardian-shell":
        return mode_shell(argv)
    if not argv:
        print(__doc__)
        return 1
    mode, args = argv[0], argv[1:]
    if mode == "check":
        return mode_check(args)
    if mode == "hook":
        return mode_hook()
    if mode == "shell":
        return mode_shell(args)
    if mode == "pause":
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        PAUSE_FILE.touch()
        print("Guardian PAUSED: every agent command will be denied.")
        return 0
    if mode == "resume":
        PAUSE_FILE.unlink(missing_ok=True)
        print("Guardian resumed.")
        return 0
    if mode == "log":
        return mode_log(args)
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
