# diary

Collects what you did recently — shell, terminal logs, Claude Code prompts, git, PRs, Slack, Linear — into one redacted markdown digest. The Workshop **Diary** schedule template (`templates/schedules/diary.json` in Workshop) runs it daily and turns that digest into journal entries, learnings and SOPs in the `diary` vault.

Split on purpose: the Go binary is a dumb, deterministic collector (stdlib only, never writes files); the judgement — what's a gotcha, what deserves an SOP — lives in the prompt.

```sh
nix-shell                          # or: direnv allow (pinned Go, golangci-lint, shellcheck)
make install                       # -> ~/go/bin/diary
# or, without a checkout: GOPRIVATE=git.chu.zone go install git.chu.zone/nozzle-industries/diary@latest
diary -since 24h -repos /repos     # markdown on stdout
```

| Flag | Default | |
|---|---|---|
| `-since` | `24h` | window |
| `-max` | `300` | per-section line cap (keeps newest) |
| `-repos` | `$DIARY_REPOS` or `$HOME` | roots scanned (depth 4) for git repos |
| `-logs` | `$DIARY_TERM_LOGS` | dirs of terminal session logs |

## Development

`make ci` runs what CI runs (vet, lint, race tests, build). `make dist` cross-compiles linux/darwin × amd64/arm64 into `dist/` with `SHA256SUMS`.

- **CI** (`.github/workflows/ci.yml`): every PR to main, all steps via `nix-shell`.
- **Release** (`.github/workflows/release.yml`): every merge to main auto-bumps the patch version from the latest `v*` tag and publishes a Forgejo release with the four binaries. Put `[release minor]`, `[release major]` or `[skip release]` in the commit subject to change that. Grab the darwin binary from the Forgejo release to run it on the Mac.

## Sources

Each is skipped when absent and listed under **Coverage** so the agent knows what it didn't see.

| Source | Needs |
|---|---|
| Environment | always: OS (macOS `sw_vers` / Linux os-release), kernel, container detection, tool versions, `docker ps` |
| Shell history | zsh (`setopt EXTENDED_HISTORY` for timestamps), bash (`HISTTIMEFORMAT` set for timestamps), fish, atuin (exit codes + cwd) |
| Terminal logs | iTerm2: Settings → Profiles → Session → *Automatically log session input to files* → point `DIARY_TERM_LOGS` at that dir. tmux: `pipe-pane`. Anything else: `script`. |
| Claude Code | `~/.claude/history.jsonl` |
| Git | your commits (`git config user.email`) + uncommitted counts |
| GitHub PRs | `gh` authenticated |
| Forgejo PRs | `tea` logged in (default login) |
| Slack | `SLACK_TOKEN` — user token with `search:read` |
| Linear | `LINEAR_API_KEY` — personal API key |

Every line passes through `redact()` (tokens, keys, passwords, URL creds, private keys) before printing. It's a regex net, not a guarantee — the prompt also forbids copying secrets.

## Getting better signal

- **macOS/Linux shell**: timestamps make or break this. zsh: `setopt EXTENDED_HISTORY INC_APPEND_HISTORY`. bash: `export HISTTIMEFORMAT='%F %T '; PROMPT_COMMAND='history -a'`. Or install atuin.
- **Docker**: containers have their own `$HOME`; mount history/`~/.claude` or run `diary` inside each and concatenate.

## Not built (yet)

Jira, Gmail/Calendar, browser history. Add a function in `main.go` when one is actually wanted.
