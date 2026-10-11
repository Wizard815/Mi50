# AI agent stack on the MI50 server

Goal: run a team of AI agents on this box, manage them from a dashboard, and stop
any agent from running harmful or runaway commands.

```
 You (browser) ──► Paperclip  (dashboard: agents, tasks, budgets, approvals)
                      │  starts agents through adapters
                      ▼
              Claude Code / OpenCode / Codex / custom process
                      │  every shell command / file write goes through ▼
                      ▼
               MI50 Guardian  (guardian/)  ── allow / ask / deny + audit log
                      │                         └─ optional 2nd opinion from the local model
                      ▼
               Linux user "agent" (no sudo) ─► workspace dirs only

 MI50 GPU ──► llama.cpp server (OpenAI-compatible API on :8080) for local models
```

## 1. Manager: Paperclip

[Paperclip](https://github.com/paperclipai/paperclip) already does what you want from
the manager. It's open source (MIT), with a Node.js server, a React UI and embedded
Postgres. It gives you org charts, tasks, per-agent budgets with hard stops,
pause/resume/terminate, approval gates and an activity log. It supports Claude Code,
Codex, OpenCode, Gemini CLI, Cursor, OpenClaw, Hermes and others, plus a generic
"custom process / HTTP" adapter.

It needs Node.js 24.11 or newer. Ubuntu 22.04's apt Node is too old, so install it
with [nvm](https://github.com/nvm-sh/nvm):

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
exec $SHELL
nvm install 24
```

Run Paperclip as the `agent` user (see step 3), never as root:

```bash
# local only (open it through an SSH tunnel: ssh -L 3100:localhost:3100 you@mi50)
npx paperclipai@latest onboard --yes
# or, to reach it from other machines on your LAN / Tailscale, with login:
npx paperclipai@latest onboard --yes --bind lan       # or --bind tailnet
```

Then open `http://localhost:3100`.

Turn these on in Paperclip:
- a **budget** with a hard stop for every agent, so a runaway agent pauses itself
- **approval** for hiring new agents
- connection actions set to **Ask first** for anything outside the workspace

## 2. Guardian: watches every command

Paperclip governs *what work* agents do. It doesn't check each shell command an
agent types. That's what `guardian/` is for. See [guardian/README.md](../guardian/README.md).

## 3. Sandbox: the part that actually keeps you safe

A command filter can always be tricked by a clever enough command. The real safety
net is that the agent *can't* do damage even if it tries:

```bash
sudo adduser --disabled-password agent     # agents run as this user
# do NOT add "agent" to sudo; DO add it to the GPU groups so it can use the MI50:
sudo usermod -aG render,video agent
```

- Keep agent work in `/home/agent/workspaces/...`. Agents don't need write access to anything else.
- Never store your personal SSH keys or cloud credentials in the `agent` account.
- Going further: run agents inside Docker/Podman with only the workspace mounted, plus
  `--device /dev/kfd --device /dev/dri` for GPU access.

## 4. Local models on the MI50 (optional)

To run agents on your own GPU instead of a paid API, serve a model with
[llama.cpp](https://github.com/ggml-org/llama.cpp). The MI50 is `gfx906`. Newer ROCm
releases dropped official gfx906 support, so the **Vulkan** build is the easiest route.
A ROCm build with `-DAMDGPU_TARGETS=gfx906` also works if you have a ROCm version that
still runs on the card.

```bash
llama-server -m /models/your-model.gguf -ngl 99 -c 32768 --host 127.0.0.1 --port 8080
```

This gives you an OpenAI-compatible API at `http://127.0.0.1:8080/v1`. Point an
OpenAI-compatible agent at it (for example OpenCode with a custom provider). The
guardian can also use it as a second opinion: set `llm_review.enabled` to `true` in
`guardian/rules.json`.
