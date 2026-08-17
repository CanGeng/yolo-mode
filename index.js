// yolo-mode - unattended full-access window for the DeepSeek Harness.
//
// WHY: when the user walks away and wants the agent to grind through a long
// task, per-call approvals and the workspace sandbox turn every wall into a
// stall. dsh already ships a `danger-full-access` permission preset; what it
// lacks for the unattended case is (a) a fast, unambiguous, HUMAN-ONLY switch,
// (b) an automatic way back, (c) a tripwire against catastrophic commands -
// the dsh sandbox governs file effects only, so fork bombs / shutdowns /
// raw-device writes sail through ANY sandbox mode - and (d) a signal back to
// the user when the work is done or something needs attention.
//
// DESIGN (interrogated via a 4-viewer pro_think round - see README):
//   * The ONLY sources of permission truth are the canonical knob events
//     (`sandbox/mode`, `approval/policy`) written through their canonical
//     setters. `yolo/armed` / `yolo/disarmed` events are derived annotations
//     (expiry + revert snapshot + audit); they never override the knobs.
//   * `/yolo` is a UI-plane command: only a human can arm or disarm. The
//     model gets NO tool to grant itself full access.
//   * The guard is a pre-execute tripwire, not a security boundary. It is
//     honestly labeled as such everywhere, including the model-facing text
//     (no risk compensation).
//   * Expiry is lazy (checked at every tool call, on a 30s sweep, and at
//     plugin start) so it survives process restarts through event replay.
//     It cannot recall already-running background processes; that residual
//     risk is documented and notified instead.
//   * Notifications bypass the tool pipeline (direct child_process / fetch /
//     socket) so the plugin's own guard can never block or loop them.

import net from 'node:net'
import tls from 'node:tls'
import { spawn } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'
import z from '@deepseek-ai/schemastery'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import {
  SANDBOX_MODES,
  effectiveSandboxMode,
  setSandboxMode,
} from '@deepseek-ai/dsh-sandbox-policy'
import {
  APPROVAL_POLICIES,
  effectiveApprovalPolicy,
  setApprovalPolicy,
} from '@deepseek-ai/dsh-user-approval'

export const name = 'yolo-mode'
export const inject = ['agents', 'approval', 'sandboxPolicy', 'sessions', 'systemPrompt', 'timer']

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit tests)
// ---------------------------------------------------------------------------

const DURATION_UNITS = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }

/**
 * Parse a human duration like "4h", "90m", "1h30m", "2d" into milliseconds.
 * A bare integer is treated as minutes. Returns null for empty input and
 * undefined for unparseable input.
 */
export function parseDuration(text) {
  const raw = String(text ?? '').trim()
  if (raw === '') return null
  if (/^\d+$/.test(raw)) {
    const minutes = Number(raw)
    return Number.isSafeInteger(minutes) && minutes > 0 ? minutes * DURATION_UNITS.m : undefined
  }
  const re = /(\d+)\s*([smhd])/g
  let total = 0
  let matched = 0
  let rest = raw
  for (let m = re.exec(raw); m !== null; m = re.exec(raw)) {
    const value = Number(m[1])
    if (!Number.isSafeInteger(value) || value <= 0) return undefined
    total += value * DURATION_UNITS[m[2]]
    matched += 1
    rest = rest.replace(m[0], '')
  }
  if (matched === 0 || rest.trim() !== '') return undefined
  return total
}

/** Human-readable rendering of a millisecond span ("2h 5m"). */
export function formatDuration(ms) {
  if (ms == null) return 'never'
  if (ms <= 0) return '0s'
  const parts = []
  const units = [
    ['d', DURATION_UNITS.d],
    ['h', DURATION_UNITS.h],
    ['m', DURATION_UNITS.m],
    ['s', DURATION_UNITS.s],
  ]
  let left = ms
  for (const [suffix, size] of units) {
    const count = Math.floor(left / size)
    if (count > 0) {
      parts.push(`${count}${suffix}`)
      left -= count * size
    }
  }
  return parts.join(' ') || '0s'
}

/** Fold the durable yolo annotation events (log order, last write wins). */
export function foldYolo(events) {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index]
    if (event.type === 'yolo/disarmed') return { armed: false, reason: event.data.reason, at: event.data.at }
    if (event.type === 'yolo/armed') {
      return {
        armed: true,
        armedAt: event.data.armedAt,
        expiresAt: event.data.expiresAt,
        revertTo: event.data.revertTo,
      }
    }
  }
  return { armed: false }
}

/**
 * The default catastrophic-core patterns. DELIBERATELY SMALL: every entry
 * must be beyond argument. Regexes over the raw command text are trivially
 * bypassable (base64, variables, eval, writing a script first) - this list
 * is a tripwire against ACCIDENTS, not a boundary against an adversary.
 */
export const DEFAULT_GUARD_PATTERNS = [
  // :(){ :|:& };: and close variants (fork bomb)
  { name: 'fork-bomb', source: String.raw`:\s*\(\s*\)\s*\{[^}]*\}\s*;\s*:` },
  // dd writing to a real block device (not /dev/null etc.)
  { name: 'dd-raw-device', source: String.raw`\bdd\b[^;&|]*\bof\s*=\s*"?\/dev\/(?!null|zero|random|urandom)(?:sd|nvme|vd|xvd|hd|mmcblk|loop|mapper)` },
  // shell truncation redirect onto a raw device
  { name: 'redirect-raw-device', source: String.raw`>\s*"?\/dev\/(?!null|zero|random|urandom|full|tcp|udp|ptmx|tty|console|fd\/)(?:sd|nvme|vd|xvd|hd|mmcblk|loop|mapper|mem|kmem|port)` },
  // filesystem creation / signature wiping on a device
  { name: 'mkfs-device', source: String.raw`\bmkfs(?:\.\w+)?\b[^;&|]*\s\/dev\/(?:sd|nvme|vd|xvd|hd|mmcblk|loop)` },
  { name: 'wipefs-all', source: String.raw`\bwipefs\b[^;&|]*\s-a\b` },
  { name: 'blkdiscard', source: String.raw`\bblkdiscard\b` },
  // recursive force-delete of /, /*, ~ or $HOME themselves (subpaths are fine)
  { name: 'rm-root', source: String.raw`\brm\b[^;&|]*\s-{1,2}[a-zA-Z]*(?:rf|fr|r[a-zA-Z]*f|f[a-zA-Z]*r)[a-zA-Z]*\b[^;&|]*\s["']?(?:--no-preserve-root\s+)?["']?(?:\/\*?|~(?:\/\*?)?|\$HOME(?:\/\*?)?)["']?(?:\s|["']|$)` },
  { name: 'rm-root-split-flags', source: String.raw`\brm\b[^;&|]*\s-[a-zA-Z]*r\b[^;&|]*\s-[a-zA-Z]*f\b[^;&|]*\s["']?(?:\/\*?|~(?:\/\*?)?|\$HOME(?:\/\*?)?)["']?(?:\s|["']|$)|\brm\b[^;&|]*\s-[a-zA-Z]*f\b[^;&|]*\s-[a-zA-Z]*r\b[^;&|]*\s["']?(?:\/\*?|~(?:\/\*?)?|\$HOME(?:\/\*?)?)["']?(?:\s|["']|$)` },
  { name: 'rm-no-preserve-root', source: String.raw`\brm\b[^;&|]*--no-preserve-root` },
  // power state (anchored so prose like `echo reboot` stays untouched)
  { name: 'shutdown-family', source: String.raw`(?:^|[;&|]\s*|(?:sudo|doas)\s+)(?:shutdown|poweroff|halt|reboot)\b|\binit\s+[06]\b|\bsystemctl\s+(?:poweroff|halt|reboot|suspend)` },
  // recursive world-writable /
  { name: 'chmod-777-root', source: String.raw`\bchmod\b[^;&|]*-R[^;&|]*\s777\s+\/(?:\s|$)` },
]

/** Paths the write/edit guard refuses to touch even under full access. */
export const DEFAULT_PROTECTED_PATHS = ['~/.ssh', '~/.gnupg', '~/.aws', '~/.config/gcloud', '~/.kube']

export function compilePatterns({ useDefaults, extra }) {
  const entries = []
  if (useDefaults !== false) entries.push(...DEFAULT_GUARD_PATTERNS)
  for (const source of extra ?? []) {
    try {
      entries.push({ name: `custom:${String(source).slice(0, 40)}`, regex: new RegExp(source, 'i') })
    } catch {
      entries.push({ name: `custom-invalid:${String(source).slice(0, 40)}`, regex: null })
    }
  }
  for (const entry of entries) {
    if (entry.regex === undefined) entry.regex = new RegExp(entry.source, 'i')
  }
  return entries
}

/** Match a bash command text against the compiled guard patterns. */
export function matchGuard(command, patterns) {
  if (typeof command !== 'string' || command === '') return undefined
  for (const entry of patterns) {
    if (entry.regex === null) continue
    if (entry.regex.test(command)) return entry
  }
  return undefined
}

/** Expand '~' lexically; resolve relatives against `cwd` when available. */
export function expandPath(target, { cwd, home } = {}) {
  const homedir = home ?? os.homedir()
  let text = String(target ?? '')
  if (text === '~') text = homedir
  else if (text.startsWith('~/')) text = path.join(homedir, text.slice(2))
  if (!path.isAbsolute(text) && cwd) text = path.join(cwd, text)
  return path.normalize(text)
}

/** Lexical protected-path containment (target == protected or beneath it). */
export function isUnderProtectedPath(target, protectedPaths) {
  for (const base of protectedPaths) {
    if (target === base || target.startsWith(base + path.sep)) return base
  }
  return undefined
}

// ---------------------------------------------------------------------------
// Minimal SMTP client (no dependencies). PLAIN auth, implicit TLS (465) or
// STARTTLS when the server offers it (587). Enough for personal relays.
// ---------------------------------------------------------------------------

export function buildEmailMessage({ from, to, subject, text, date }) {
  const when = date ?? new Date()
  const lines = String(text ?? '').split(/\r?\n/)
  const body = lines.map((line) => (line.startsWith('.') ? `.${line}` : line)).join('\r\n')
  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${when.toUTCString()}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    '',
  ]
  return `${headers.join('\r\n')}${body}\r\n`
}

class SmtpDialog {
  constructor() {
    this.buffer = ''
    this.pending = null
    this.socket = null
  }
  attach(socket) {
    this.socket = socket
    socket.setEncoding('utf8')
    socket.on('data', (chunk) => {
      this.buffer += chunk
      this.tryResolve()
    })
    socket.on('error', (error) => this.reject(error))
  }
  reject(error) {
    if (this.pending) {
      const { reject: fn } = this.pending
      this.pending = null
      fn(error)
    }
  }
  /**
   * Consume the next complete SMTP reply: consecutive lines `NNN-text` may
   * precede the terminating `NNN text`. Resolves with the code plus the full
   * joined reply text (so EHLO capabilities stay visible).
   */
  tryResolve() {
    while (this.pending !== null) {
      let cursor = 0
      let code = null
      const lines = []
      for (;;) {
        const nl = this.buffer.indexOf('\r\n', cursor)
        if (nl === -1) return // reply still incomplete
        const line = this.buffer.slice(cursor, nl)
        cursor = nl + 2
        if (/^\d{3} /.test(line)) {
          code = Number(line.slice(0, 3))
          lines.push(line.slice(4))
          break
        }
        if (/^\d{3}-/.test(line)) {
          lines.push(line.slice(4))
          continue
        }
        // Non-reply noise before a complete reply: skip the line.
      }
      this.buffer = this.buffer.slice(cursor)
      const { resolve: fn } = this.pending
      this.pending = null
      fn({ code, text: lines.join('\n') })
    }
  }
  expect() {
    if (this.pending) throw new Error('yolo notify: smtp dialog overflow')
    return new Promise((resolve, reject) => {
      this.pending = { resolve, reject }
      this.tryResolve()
    })
  }
  send(line) {
    this.socket.write(`${line}\r\n`)
  }
}

export async function sendEmail(cfg, subject, text) {
  if (!cfg.host || !cfg.to) throw new Error('yolo notify: email host/to not configured')
  const from = cfg.from || cfg.user
  const socket = cfg.secure
    ? tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host })
    : net.connect({ host: cfg.host, port: cfg.port })
  socket.setTimeout(20_000)
  socket.on('timeout', () => socket.destroy(new Error('yolo notify: smtp timeout')))
  const dialog = new SmtpDialog()
  try {
    await new Promise((resolve, reject) => {
      socket.once(cfg.secure ? 'secureConnect' : 'connect', resolve)
      socket.once('error', reject)
    })
    dialog.attach(socket)
    const ok = (reply, what) => {
      if (Math.floor(reply.code / 100) !== 2 && Math.floor(reply.code / 100) !== 3) {
        throw new Error(`smtp ${what}: [${reply.code}] ${reply.text}`)
      }
    }
    let reply = await dialog.expect()
    ok(reply, 'greeting')
    dialog.send('EHLO dsh-yolo')
    reply = await dialog.expect()
    ok(reply, 'ehlo')
    if (!cfg.secure && /\bSTARTTLS\b/i.test(reply.text)) {
      dialog.send('STARTTLS')
      reply = await dialog.expect()
      ok(reply, 'starttls')
      const upgraded = tls.connect({ socket, servername: cfg.host })
      await new Promise((resolve, reject) => {
        upgraded.once('secureConnect', resolve)
        upgraded.once('error', reject)
      })
      dialog.attach(upgraded)
      dialog.send('EHLO dsh-yolo')
      reply = await dialog.expect()
      ok(reply, 'ehlo(tls)')
    }
    if (cfg.user && cfg.pass !== undefined && cfg.pass !== '') {
      const plain = Buffer.from(`\0${cfg.user}\0${cfg.pass}`, 'utf8').toString('base64')
      dialog.send(`AUTH PLAIN ${plain}`)
      reply = await dialog.expect()
      if (Math.floor(reply.code / 100) !== 2) throw new Error(`smtp auth: [${reply.code}] ${reply.text}`)
    }
    dialog.send(`MAIL FROM:<${from}>`)
    reply = await dialog.expect()
    ok(reply, 'mail from')
    for (const recipient of String(cfg.to).split(',').map((item) => item.trim()).filter(Boolean)) {
      dialog.send(`RCPT TO:<${recipient}>`)
      reply = await dialog.expect()
      ok(reply, 'rcpt')
    }
    dialog.send('DATA')
    reply = await dialog.expect()
    if (Math.floor(reply.code / 100) !== 3) throw new Error(`smtp data: [${reply.code}] ${reply.text}`)
    dialog.socket.write(`${buildEmailMessage({ from, to: cfg.to, subject, text })}\r\n.\r\n`)
    reply = await dialog.expect()
    ok(reply, 'body')
    dialog.send('QUIT')
    await dialog.expect().catch(() => {})
  } finally {
    socket.destroy()
  }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export const Config = z.object({
  guard: z.object({
    mode: z.union(['always', 'yolo-only', 'off']).default('always'),
    useDefaults: z.boolean().default(true),
    patterns: z.array(z.string()).default([]),
    useDefaultProtectedPaths: z.boolean().default(true),
    protectedPaths: z.array(z.string()).default([]),
    maxStrikes: z.number().default(3),
  }).default({}),
  notify: z.object({
    desktop: z.object({ command: z.string().default('') }).default({}),
    webhook: z.object({ url: z.string().default(''), headers: z.dict(z.string()).default({}) }).default({}),
    email: z.object({
      host: z.string().default(''),
      port: z.number().default(465),
      secure: z.boolean().default(true),
      user: z.string().default(''),
      pass: z.string().default(''),
      from: z.string().default(''),
      to: z.string().default(''),
    }).default({}),
  }).default({}),
  context: z.object({
    enabled: z.boolean().default(true),
    order: z.number().default(116),
  }).default({}),
})

/** Defensive normalization: correct config even if the loader skipped the schema. */
function normalizeConfig(raw) {
  const config = raw ?? {}
  const guard = config.guard ?? {}
  const notify = config.notify ?? {}
  const context = config.context ?? {}
  const desktop = notify.desktop ?? {}
  const webhook = notify.webhook ?? {}
  const email = notify.email ?? {}
  return {
    guard: {
      mode: ['always', 'yolo-only', 'off'].includes(guard.mode) ? guard.mode : 'always',
      useDefaults: guard.useDefaults !== false,
      patterns: Array.isArray(guard.patterns) ? guard.patterns.filter((item) => typeof item === 'string') : [],
      useDefaultProtectedPaths: guard.useDefaultProtectedPaths !== false,
      protectedPaths: Array.isArray(guard.protectedPaths) ? guard.protectedPaths.filter((item) => typeof item === 'string') : [],
      maxStrikes: Number.isFinite(guard.maxStrikes) && guard.maxStrikes >= 0 ? Math.floor(guard.maxStrikes) : 3,
    },
    notify: {
      desktop: { command: typeof desktop.command === 'string' ? desktop.command : '' },
      webhook: {
        url: typeof webhook.url === 'string' ? webhook.url : '',
        headers: webhook.headers && typeof webhook.headers === 'object' ? webhook.headers : {},
      },
      email: {
        host: typeof email.host === 'string' ? email.host : '',
        port: Number.isFinite(email.port) ? email.port : 465,
        secure: email.secure !== false,
        user: typeof email.user === 'string' ? email.user : '',
        pass: typeof email.pass === 'string' ? email.pass : '',
        from: typeof email.from === 'string' ? email.from : '',
        to: typeof email.to === 'string' ? email.to : '',
      },
    },
    context: {
      enabled: context.enabled !== false,
      order: Number.isFinite(context.order) ? context.order : 116,
    },
  }
}

// ---------------------------------------------------------------------------
// Model-facing runtime context (cache-safe: byte-identical while unchanged)
// ---------------------------------------------------------------------------

function yoloContextText(state) {
  if (!state.armed) return ''
  const expiry = state.expiresAt == null
    ? 'It does not expire until the user turns it off (/yolo off).'
    : `It expires at ${new Date(state.expiresAt).toISOString()}; the session then returns to its prior permissions automatically.`
  return [
    'Current DSH yolo mode: ARMED (unattended full-access window).',
    'The file sandbox is danger-full-access and approval prompts are disabled.',
    'The user is away. Work autonomously: make reasonable default choices, record them for the final report, and keep making progress instead of calling ask_user_question - nobody will answer promptly. Batch any genuinely blocking questions into ONE ask at the end.',
    expiry,
    'A best-effort catastrophic-command tripwire guard is active (fork bombs, raw-device writes, root-level deletions, shutdown-family commands). It is a tripwire, NOT a security boundary; a denial from it is FINAL for that command - do not rephrase, obfuscate, or retry a blocked command.',
    'Background processes started in this window keep their permissions after expiry; the user will review the full session log afterwards.',
  ].join(' ')
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

const TICK_MS = 30_000
const IDLE_NOTIFY_MIN_INTERVAL_MS = 5 * 60_000
const YOLO_SANDBOX = 'danger-full-access'
const YOLO_APPROVAL = 'never'

export function apply(ctx, rawConfig) {
  const config = normalizeConfig(rawConfig)
  const logger = ctx.logger ?? console

  const patterns = compilePatterns({
    useDefaults: config.guard.useDefaults,
    extra: config.guard.patterns,
  })
  const home = os.homedir()
  const protectedPaths = [
    ...(config.guard.useDefaultProtectedPaths ? DEFAULT_PROTECTED_PATHS : []),
    ...config.guard.protectedPaths,
  ].map((entry) => expandPath(entry, { home }))

  const strikes = new Map() // sessionId -> denial count while armed
  const lastIdleNotify = new Map() // sessionId -> epoch ms

  const yoloOf = (session) => foldYolo(session.events)
  const expired = (state) => state.armed && state.expiresAt != null && Date.now() >= state.expiresAt

  // -- notifications (never routed through the tool pipeline) ---------------

  function notify(event, detail, sessionId) {
    const at = new Date().toISOString()
    const payload = { event, detail: String(detail ?? '').slice(0, 500), sessionId: sessionId ?? null, at }
    const template = config.notify.desktop.command
    if (template) {
      const command = template
        .replaceAll('{event}', payload.event)
        .replaceAll('{detail}', payload.detail.replaceAll('"', "'"))
        .replaceAll('{sessionId}', payload.sessionId ?? '')
        .replaceAll('{time}', payload.at)
      try {
        const child = spawn(command, { shell: true, stdio: 'ignore' })
        child.on('error', (error) => logger.warn(`yolo-mode desktop notify failed: ${error.message}`))
      } catch (error) {
        logger.warn(`yolo-mode desktop notify failed: ${error.message}`)
      }
    }
    if (config.notify.webhook.url) {
      fetch(config.notify.webhook.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...config.notify.webhook.headers },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10_000),
      }).catch((error) => logger.warn(`yolo-mode webhook notify failed: ${error.message}`))
    }
    if (config.notify.email.host && config.notify.email.to) {
      sendEmail(
        config.notify.email,
        `[dsh yolo] ${event}`,
        [
          `event: ${event}`,
          `session: ${payload.sessionId ?? '(none)'}`,
          `time: ${at}`,
          '',
          payload.detail,
        ].join('\n'),
      ).catch((error) => logger.warn(`yolo-mode email notify failed: ${error.message}`))
    }
  }

  // -- arm / disarm ---------------------------------------------------------

  async function arm(agent, durationMs) {
    const session = agent.session
    const previous = yoloOf(session)
    // Preserve the ORIGINAL revert target across re-arms.
    const revertTo = previous.armed
      ? previous.revertTo
      : {
          sandbox: effectiveSandboxMode(session.events) ?? ctx.sandboxPolicy.defaultMode,
          approval: effectiveApprovalPolicy(session.events) ?? ctx.approval.config.policy ?? 'ask',
        }
    if (!SANDBOX_MODES.includes(revertTo.sandbox)) revertTo.sandbox = 'read-only'
    if (!APPROVAL_POLICIES.includes(revertTo.approval)) revertTo.approval = 'ask'

    const now = Date.now()
    const expiresAt = durationMs == null ? null : now + durationMs
    setSandboxMode(session, YOLO_SANDBOX)
    await ctx.approval.setPolicy(agent, YOLO_APPROVAL)
    session.append('yolo/armed', { armedAt: now, expiresAt, revertTo })
    strikes.set(session.id, 0)
    try { await ctx.sessions.flush(session) } catch { /* best effort */ }
    notify('armed', `yolo armed${expiresAt ? ` until ${new Date(expiresAt).toISOString()}` : ' with no expiry'}; revert target sandbox=${revertTo.sandbox} approval=${revertTo.approval}`, session.id)
    logger.info(`yolo-mode armed on session ${session.id}${expiresAt ? ` (expires ${new Date(expiresAt).toISOString()})` : ' (no expiry)'}`)
    return expiresAt
  }

  const DISARM_NOTICES = {
    manual: 'The user turned yolo mode off.',
    expired: 'The unattended full-access window EXPIRED.',
    strikes: 'Yolo mode was DISABLED by the guard circuit breaker after repeated catastrophic-command denials.',
  }

  async function disarm(session, reason) {
    const state = yoloOf(session)
    if (!state.armed) return false
    const agent = ctx.agents.get(session.id)
    if (effectiveSandboxMode(session.events) === YOLO_SANDBOX) {
      setSandboxMode(session, state.revertTo.sandbox)
    }
    if (effectiveApprovalPolicy(session.events) === YOLO_APPROVAL) {
      if (agent) await ctx.approval.setPolicy(agent, state.revertTo.approval)
      else setApprovalPolicy(session, state.revertTo.approval)
    }
    session.append('yolo/disarmed', { at: Date.now(), reason })
    strikes.delete(session.id)
    try { await ctx.sessions.flush(session) } catch { /* best effort */ }
    if (agent) {
      agent.inject(createUserMessage({
        content: [{ type: 'text', text: `${DISARM_NOTICES[reason] ?? DISARM_NOTICES.manual} The session is back to sandbox=${state.revertTo.sandbox}, approval=${state.revertTo.approval}. Continue the task within these limits; if full access is genuinely still required, the user must re-arm it (/yolo on).` }],
        source: { kind: 'plugin', plugin: 'yolo-mode' },
      }))
    }
    notify(`disarmed:${reason}`, DISARM_NOTICES[reason] ?? DISARM_NOTICES.manual, session.id)
    logger.info(`yolo-mode disarmed on session ${session.id} (${reason})`)
    return true
  }

  // -- expiry machinery: lazy check + 30s sweep + start sweep ----------------

  const sweep = async () => {
    for (const session of ctx.sessions.list()) {
      try {
        if (expired(yoloOf(session))) await disarm(session, 'expired')
      } catch (error) {
        logger.warn(`yolo-mode expiry sweep failed on session ${session.id}: ${error.message}`)
      }
    }
  }
  ctx.setInterval(() => { sweep().catch(() => {}) }, TICK_MS)
  sweep().catch(() => {}) // restart-replay sweep: revive-and-revert immediately

  // -- guard + lazy expiry at the tool pipeline ------------------------------

  ctx.on('tools/pre-execute', async (exec, next) => {
    const agent = exec.agent
    if (agent?.session) {
      const state = yoloOf(agent.session)
      if (expired(state)) {
        try { await disarm(agent.session, 'expired') } catch { /* denial path stays safe */ }
      }
    }
    if (config.guard.mode !== 'off' && agent?.session) {
      const armed = yoloOf(agent.session).armed
      const active = config.guard.mode === 'always' || armed
      if (active) {
        // bash catastrophic tripwire
        if (exec.name === 'bash' && typeof exec.arguments?.command === 'string') {
          const hit = matchGuard(exec.arguments.command, patterns)
          if (hit) {
            const session = agent.session
            const count = (strikes.get(session.id) ?? 0) + 1
            strikes.set(session.id, count)
            notify('guard-denied', `bash command matched "${hit.name}" (strike ${count}${armed && config.guard.maxStrikes > 0 ? `/${config.guard.maxStrikes}` : ''})`, session.id)
            if (armed && config.guard.maxStrikes > 0 && count >= config.guard.maxStrikes) {
              try { await disarm(session, 'strikes') } catch { /* already reported */ }
            }
            return {
              kind: 'deny',
              reason: `yolo-mode guard: this command matched the catastrophic pattern "${hit.name}". The guard is a best-effort tripwire against accidents, not a security boundary; this denial is FINAL for this command - do not rephrase, encode, or retry it. If the operation is genuinely required, the human must run it themselves or disable the guard.`,
            }
          }
        }
        // write/edit protected paths
        if ((exec.name === 'write' || exec.name === 'edit') && typeof exec.arguments?.file_path === 'string') {
          const target = expandPath(exec.arguments.file_path, { cwd: agent.session.header?.cwd, home })
          const base = isUnderProtectedPath(target, protectedPaths)
          if (base) {
            notify('guard-denied', `${exec.name} into protected path ${base}`, agent.session.id)
            return {
              kind: 'deny',
              reason: `yolo-mode guard: "${exec.arguments.file_path}" resolves under the protected path "${base}" (credentials/key material). This denial is final; do not try other tools or paths to reach it. If a change there is genuinely required, the human must make it.`,
            }
          }
        }
      }
    }
    return next()
  }, { prepend: true })

  // -- idle notification while armed -----------------------------------------

  ctx.on('agent/status', ({ agent, status }) => {
    if (status !== 'idle' || !agent?.session) return
    const state = yoloOf(agent.session)
    if (!state.armed) return
    const now = Date.now()
    const last = lastIdleNotify.get(agent.session.id) ?? 0
    if (now - last < IDLE_NOTIFY_MIN_INTERVAL_MS) return
    lastIdleNotify.set(agent.session.id, now)
    notify('idle', 'the agent finished its work and is now idle (awaiting user attention)', agent.session.id)
  })

  // -- model-facing runtime context ------------------------------------------

  if (config.context.enabled) {
    ctx.systemPrompt.context({
      name: 'yolo:policy',
      order: config.context.order,
      text: (ctxContext) => {
        const agent = ctxContext.agent
        if (agent === undefined) return ''
        return yoloContextText(yoloOf(agent.session))
      },
    })
  }

  // -- the human-only /yolo command ------------------------------------------

  ctx.inject(['commands'], (scope) => {
    scope.commands.register({
      name: 'yolo',
      description: 'Toggle unattended full-access mode: /yolo on [duration] | /yolo off | /yolo status',
      input: { hint: 'on [4h|90m|2d] | off | status' },
      handler: async ({ agent, rawInput }) => {
        const session = agent.session
        const arg = String(rawInput ?? '').trim()
        const [head, ...rest] = arg.split(/\s+/)
        const state = yoloOf(session)

        if (head === '' || head === 'status') {
          const lines = []
          if (state.armed) {
            const remaining = state.expiresAt == null ? 'no expiry' : `${formatDuration(state.expiresAt - Date.now())} remaining (at ${new Date(state.expiresAt).toISOString()})`
            lines.push(`yolo ARMED - ${remaining}`)
            lines.push(`revert target: sandbox=${state.revertTo.sandbox}, approval=${state.revertTo.approval}`)
            const strikeCount = strikes.get(session.id) ?? 0
            lines.push(`guard strikes: ${strikeCount}${config.guard.maxStrikes > 0 ? `/${config.guard.maxStrikes}` : ' (breaker off)'}`)
          } else {
            lines.push('yolo not armed')
          }
          const channels = [
            config.notify.desktop.command ? 'desktop' : null,
            config.notify.webhook.url ? 'webhook' : null,
            config.notify.email.host && config.notify.email.to ? 'email' : null,
          ].filter(Boolean)
          lines.push(`guard: ${config.guard.mode} (${patterns.length} pattern${patterns.length === 1 ? '' : 's'}, ${protectedPaths.length} protected paths)`)
          lines.push(`notify channels: ${channels.length ? channels.join(', ') : 'none'}`)
          return { kind: 'success', text: lines.join('\n') }
        }

        if (head === 'on') {
          const durationText = rest.join(' ')
          const durationMs = parseDuration(durationText)
          if (durationText !== '' && durationMs === undefined) {
            return { kind: 'error', text: `invalid duration "${durationText}" - use forms like 30m, 4h, 1h30m, 2d, or a bare number of minutes; omit for no expiry` }
          }
          const expiresAt = await arm(agent, durationMs)
          const expiryText = expiresAt == null
            ? 'no expiry - stays armed until /yolo off'
            : `expires at ${new Date(expiresAt).toISOString()} (${formatDuration(durationMs)})`
          return {
            kind: 'success',
            text: [
              'yolo ARMED: sandbox=danger-full-access, approval=never.',
              expiryText,
              'The model was told the user is away and to work autonomously.',
              'Catastrophic-command guard is active; repeated denials disarm yolo automatically.',
            ].join('\n'),
          }
        }

        if (head === 'off') {
          const done = await disarm(session, 'manual')
          return {
            kind: done ? 'success' : 'error',
            text: done ? 'yolo DISARMED - permissions reverted to the pre-arm snapshot.' : 'yolo was not armed.',
          }
        }

        return { kind: 'error', text: 'usage: /yolo on [4h|90m|2d] | /yolo off | /yolo status' }
      },
    })
  })
}
