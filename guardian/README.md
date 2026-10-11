# MI50 Guardian

The guardian checks every command an AI agent tries to run, **before** it runs.

| Verdict | Examples | What happens |
|---|---|---|
| **deny** | `sudo …`, `rm -rf /`, `curl … \| bash`, `reboot`, `mkfs`, `rocm-smi --setsclk`, `amdvbflash`, writes to `/etc` or `~/.ssh`, `git push --force` | blocked |
| **ask** | `pip install`, `apt install`, `systemctl restart`, `rm -r build`, `git push`, unknown tools | a human approves it; with no human present it's blocked |
| **allow** | `ls`, `cat`, `grep`, `git status/diff/commit`, `python …`, `pytest`, `rocm-smi --showtemp` | runs |

It also catches agents that go **out of whack**:
- **Loop guard:** the same command 6 times in 2 minutes gets blocked, because the agent is stuck.
- **Rate limit:** more than 60 commands a minute gets blocked, because the agent is running wild.
- **Kill switch:** `./guardian.py pause` blocks *everything* until you run `./guardian.py resume`.
- **Audit log:** every decision is saved to `~/.local/state/mi50-guardian/audit.jsonl`. View it with `./guardian.py log 50`.
- **Optional AI second opinion:** commands that no rule covers can be sent to your local
  llama.cpp model (`llm_review` in `rules.json`). If the model is down, the command falls back to "ask".

It needs only Python 3 (standard library, works on Ubuntu 22.04). There's nothing to install.

## Try it

```bash
./guardian.py check "rm -rf /"          # DENY: recursive delete of root/home   (exit 2)
./guardian.py check "pip install torch" # ASK: installs packages                 (exit 1)
./guardian.py check "git status"        # ALLOW: matches allow rules             (exit 0)
python3 test_guardian.py                # run the tests
```

## Hook it into your agents

**Claude Code** (including when Paperclip runs it): add this to the agent user's
`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit",
        "hooks": [{ "type": "command", "command": "/home/agent/Mi50/guardian/guardian.py hook" }]
      }
    ]
  }
}
```

**Other agents (OpenCode, Codex, custom process adapters, scripts):** use the guardian as
the agent's shell. `guardian-shell` checks each `$SHELL -c "…"` command and only then
hands it to the real bash:

```bash
export SHELL=/home/agent/Mi50/guardian/guardian-shell
```

Different tools pick their shell in different ways. After setting it up, ask the agent to
run `sudo true`. If you see a `MI50 Guardian blocked` message and a new entry in
`./guardian.py log`, it's wired in.

## Tuning

Edit `rules.json`. Each rule is a `[regex, reason]` pair, and the strictest match wins
(deny > ask > allow). Commands that match no rule get `unknown_action` (default
`ask`). Set `ask_when_unattended` to `"allow"` only if you trust your agents more than
the rules.

## Be honest about the limits

This is a seatbelt, not a vault. A determined or confused agent can hide a command
from pattern matching, for example by writing a script and then running it. Always
combine the guardian with the sandbox in [docs/agent-stack.md](../docs/agent-stack.md#3-sandbox-the-part-that-actually-keeps-you-safe):
a separate `agent` user with no sudo, so even a missed command can't hurt the system.
