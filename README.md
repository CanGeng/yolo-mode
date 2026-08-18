# yolo-mode

English | [中文](README.zh.md)

An **unattended full-access window** plugin for the [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`): when you walk away and want the agent to grind through a long task, one human-only command — `/yolo on` — arms `danger-full-access` sandbox + `never` approval for that session, with an automatic way back, a tripwire against catastrophic commands, and notifications when the work is done or something needs attention.

> **Read this first.** In yolo mode the model executes with *your* uid and full filesystem reach — every operation is equivalent to your own. The bundled guard is a **best-effort tripwire against accidents, not a security boundary** (a regex blocklist is trivially bypassed by deliberate obfuscation). Arm it only for sessions whose task you would be comfortable running yourself. See [Residual risks](#residual-risks).

## Why

Per-call approvals and the workspace sandbox turn every wall into a stall when nobody is at the keyboard. dsh already ships a `danger-full-access` permission preset; what the unattended case additionally needs is:

- a fast, unambiguous, **human-only** switch (the model never gets a tool to grant itself access),
- an **automatic way back** (time-boxed expiry, circuit breaker),
- a guard for the operations **no dsh sandbox mode stops** — the file sandbox governs file effects only, so fork bombs, shutdowns, and raw-device writes sail through `workspace-write` too,
- a signal back to you (idle / denial / disarm notifications).

## Usage

| Command | Effect |
|---|---|
| `/yolo on` | Arm (no expiry by default, until `/yolo off`) |
| `/yolo on 4h` · `/yolo on 90m` · `/yolo on 1h30m` · `/yolo on 2d` · `/yolo on 45` (bare number = minutes) | Arm with an expiry; auto-reverts when it passes |
| `/yolo off` | Disarm now; reverts to the pre-arm permission snapshot |
| `/yolo status` | Armed state, remaining time, revert target, guard strike count, notify channels |

Arming writes the canonical `sandbox/mode` and `approval/policy` session events through their canonical setters, so the model-visible runtime context updates immediately, the state survives restarts via log replay, and the Web UI's permission selector shows `danger-full-access`.

## How it works

1. **The only permission truth is the canonical knob events.** `yolo/armed` / `yolo/disarmed` are derived annotations (expiry, revert snapshot, audit) that never override the knobs — consistent with dsh's log-only + replay philosophy.
2. **Only a human can arm.** `/yolo` runs on the UI command plane; the model has no tool to arm yolo, and the guard's circuit breaker only ever *disarms*.
3. **Expiry is lazy and restart-safe.** `expiresAt` is checked at every tool call, on a 30-second sweep, and at plugin start; a revived session with a stale window reverts immediately. Already-running background processes are *not* killed (long tasks are the point) — the residual risk is notified instead.
4. **The guard is honest about what it is.** It labels itself a tripwire everywhere, including the model-facing text (no risk compensation), and its denials are final per command: no rephrasing, encoding, or retrying.
5. **Notifications never touch the tool pipeline.** Desktop command / webhook / SMTP email run via direct `child_process` / `fetch` / socket, so the plugin's own guard can never block or loop them.

## Guard

- `tools/pre-execute` listener; `mode: always | yolo-only | off` (default `always` — see *Why*).
- **Catastrophic core list** (deliberately tiny and beyond argument): fork bombs; `dd` / redirects onto raw devices; `mkfs` / `wipefs` / `blkdiscard`; `rm -rf` on bare `/`, `/*`, `~`, `$HOME` (split flags, quotes, globs, `--no-preserve-root` variants covered; subpaths pass); shutdown / poweroff / halt / reboot / `init 0|6` / `systemctl poweroff` (anchored to command position so prose like `echo reboot` is untouched); `chmod -R 777 /`.
- **Protected paths:** the `write`/`edit` tools may not touch `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gcloud`, `~/.kube` (lexical prefix match, configurable).
- **Circuit breaker:** while armed, accumulated guard denials reaching `maxStrikes` (default 3, `0` disables) disarm yolo automatically and notify.
- Custom regexes append to `guard.patterns`; a pattern that fails to compile is skipped, never fatal.

## Model experience

While armed, a cache-stable runtime-context section (`yolo:policy`) tells the model: full-access window active; the user is away — work autonomously, make and record reasonable default choices, batch genuinely blocking questions into one ask at the end; the expiry instant; the tripwire's existence and finality; the background-process residual risk; and that the full session log will be reviewed afterwards. When not armed the section is empty — zero tokens.

## Notifications (all off by default)

| Event | Fires when |
|---|---|
| `armed` / `disarmed:manual` / `disarmed:expired` / `disarmed:strikes` | Switch and revert |
| `guard-denied` | A guard denial (pattern name + strike count) |
| `idle` | The agent goes idle while armed (work finished / needs a human); rate-limited to once per 5 minutes per session |

Three channels, usable together — see [cordis.patch.yml](cordis.patch.yml) for every field:

```yaml
notify:
  desktop:
    command: 'notify-send "dsh yolo" "{event}: {detail}"'   # {event} {detail} {sessionId} {time}
  webhook:
    url: https://example.com/hook    # POSTs {event, detail, sessionId, at} as JSON
  email:                             # built-in minimal SMTP client (PLAIN auth; implicit TLS 465 or STARTTLS)
    host: smtp.example.com
    port: 465
    secure: true
    user: bot@example.com
    pass: app-password
    from: bot@example.com
    to: me@example.com
```

## Residual risks

Accepted knowingly, in exchange for autonomy:

- The regex tripwire is bypassable by deliberate obfuscation (base64, variable splicing, writing a script first); it protects against **accidents**, not adversaries.
- Subagents and background processes started while armed keep the permissions they were born with, past expiry.
- Expiry can lag up to ~30 seconds plus one tool-call interval; a long in-flight generation is not interrupted.
- Under `danger-full-access` the `write`/`edit` tools reach the whole disk — the protected-path list covers only what is configured.
- If your dsh Web endpoint has no authentication, any local process or page that can reach it can already operate the UI (a dsh deployment fact, not introduced by this plugin).
- Everything — every tool call and guard decision — lands in the session log for later review in the GUI.

## Session readability drift (uninstalling this plugin)

dsh's persistence layer refuses to load a session log containing event types outside its built-in `KNOWN_SESSION_EVENT_TYPES` set (unless an event carries `ignorable:true` — which `Session.append()` cannot set as of 0.1.0-rc.6). `/yolo on|off` writes `yolo/armed` / `yolo/disarmed` annotation events into the log, so this plugin registers both types into that set at load time. Consequence:

- **While this plugin is loaded**, yolo sessions load normally.
- **If you uninstall it** (or disable its loading), any session that ever ran `/yolo` will fail to open with `SessionFormatUnsupportedError` until the plugin is restored, or the `yolo/*` lines in the log are given `"ignorable": true` (one-line JSON edit per event; `decodeStorageRecord` passes them through untouched).

In short: session readability depends on the plugin's presence. This is a harness-side API gap (write path accepts anything, read path vets a closed vocabulary, and no writer for `ignorable` exists) — not a choice this plugin can opt out of on stock dsh. Before uninstalling, patch the logs as described above; a repair script is straightforward (decompress `session.jsonl.zstd`, add `"ignorable": true` to `yolo/*` lines, recompress).

## Install

```sh
# 1. Clone anywhere and link it into your profile's node_modules
git clone https://github.com/CanGeng/yolo-mode.git
ln -sfn "$(pwd)/yolo-mode" ~/.dsh/profiles/node_modules/yolo-mode

# 2. Append the insert row from this repo's cordis.patch.yml
#    to ~/.dsh/profiles/web/cordis.patch.yml

# 3. Restart dsh web, then verify with /yolo status in a session
```

## Configuration

Every knob lives in the `yolo-mode` row of your profile's `cordis.patch.yml` — see [cordis.patch.yml](cordis.patch.yml) for the annotated default configuration (`guard.*`, `notify.*`, `context.*`).

## Testing

```sh
node test.mjs   # 22 cases: duration parsing / event fold / guard positive+negative / path protection / email message / fake-SMTP dialogue
```

## License

[MIT](LICENSE)
