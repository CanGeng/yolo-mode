// yolo-mode unit tests: duration parsing, guard patterns, yolo fold, path
// protection, email message building, and a fake-SMTP integration dialogue.
// Run: node test.mjs

import assert from 'node:assert/strict'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import {
  apply,
  buildEmailMessage,
  compilePatterns,
  expandPath,
  foldYolo,
  formatDuration,
  isUnderProtectedPath,
  matchGuard,
  name,
  parseDuration,
  sendEmail,
} from './index.js'

const MIN = 60_000
const HOUR = 60 * MIN
const DAY = 24 * HOUR

let passed = 0
let failed = 0
/** Sync or async test case; async failures surface as FAIL, not unhandled rejections. */
function test(title, fn) {
  const done = () => {
    passed += 1
    console.log(`ok   ${title}`)
  }
  const fail = (error) => {
    failed += 1
    console.error(`FAIL ${title}\n     ${error.message}`)
  }
  try {
    const result = fn()
    if (result && typeof result.then === 'function') return result.then(done, fail)
  } catch (error) {
    fail(error)
    return
  }
  done()
}

await (async () => {
  // -- module shape ----------------------------------------------------------
  test('module exports the cordis plugin contract', () => {
    assert.equal(name, 'yolo-mode')
    assert.equal(typeof apply, 'function')
  })

  // -- parseDuration -----------------------------------------------------------
  test('parseDuration: empty -> null (no expiry)', () => {
    assert.equal(parseDuration(''), null)
    assert.equal(parseDuration(undefined), null)
  })
  test('parseDuration: simple units', () => {
    assert.equal(parseDuration('30m'), 30 * MIN)
    assert.equal(parseDuration('4h'), 4 * HOUR)
    assert.equal(parseDuration('2d'), 2 * DAY)
    assert.equal(parseDuration('45s'), 45_000)
  })
  test('parseDuration: compound and bare-integer forms', () => {
    assert.equal(parseDuration('1h30m'), HOUR + 30 * MIN)
    assert.equal(parseDuration('2d12h'), 2 * DAY + 12 * HOUR)
    assert.equal(parseDuration('90'), 90 * MIN)
  })
  test('parseDuration: garbage -> undefined', () => {
    assert.equal(parseDuration('4x'), undefined)
    assert.equal(parseDuration('abc'), undefined)
    assert.equal(parseDuration('-5m'), undefined)
    assert.equal(parseDuration('4h xyz'), undefined)
    assert.equal(parseDuration('0'), undefined)
  })

  test('formatDuration renders human spans', () => {
    assert.equal(formatDuration(null), 'never')
    assert.equal(formatDuration(HOUR + 30 * MIN), '1h 30m')
    assert.equal(formatDuration(45_000), '45s')
  })

  // -- foldYolo ----------------------------------------------------------------
  const armed = { type: 'yolo/armed', data: { armedAt: 1, expiresAt: 100, revertTo: { sandbox: 'workspace-write', approval: 'ask' } } }
  const disarmed = { type: 'yolo/disarmed', data: { at: 2, reason: 'manual' } }
  test('foldYolo: empty log -> not armed', () => {
    assert.equal(foldYolo([]).armed, false)
  })
  test('foldYolo: armed event survives other events', () => {
    const state = foldYolo([{ type: 'tool/result', data: {} }, armed, { type: 'tool/result', data: {} }])
    assert.equal(state.armed, true)
    assert.equal(state.expiresAt, 100)
    assert.deepEqual(state.revertTo, { sandbox: 'workspace-write', approval: 'ask' })
  })
  test('foldYolo: last write wins across arm/disarm', () => {
    assert.equal(foldYolo([armed, disarmed]).armed, false)
    const again = { type: 'yolo/armed', data: { armedAt: 3, expiresAt: null, revertTo: { sandbox: 'read-only', approval: 'ask' } } }
    const state = foldYolo([armed, disarmed, again])
    assert.equal(state.armed, true)
    assert.equal(state.expiresAt, null)
  })

  // -- guard patterns ------------------------------------------------------------
  const patterns = compilePatterns({ useDefaults: true, extra: [] })
  const deny = (command) => matchGuard(command, patterns)?.name
  const allow = (command) => assert.equal(matchGuard(command, patterns), undefined, `expected allow: ${command}`)

  test('guard: fork bomb denied', () => {
    assert.equal(deny(':(){ :|:& };:'), 'fork-bomb')
    assert.equal(deny(': ( ) { : | : & } ; :'), 'fork-bomb')
  })
  test('guard: raw-device dd / redirects denied', () => {
    assert.equal(deny('dd if=/dev/zero of=/dev/sda bs=1M count=10'), 'dd-raw-device')
    assert.equal(deny('dd of=/dev/nvme0n1'), 'dd-raw-device')
    assert.equal(deny('echo x > /dev/sda'), 'redirect-raw-device')
    assert.equal(deny('truncate -s 0 > /dev/mem'), 'redirect-raw-device')
  })
  test('guard: mkfs / wipefs / blkdiscard denied', () => {
    assert.equal(deny('mkfs.ext4 /dev/sdb1'), 'mkfs-device')
    assert.equal(deny('mkfs /dev/vda'), 'mkfs-device')
    assert.equal(deny('wipefs -a /dev/sda'), 'wipefs-all')
    assert.equal(deny('blkdiscard /dev/nvme0n1'), 'blkdiscard')
  })
  test('guard: root-level rm denied (combined, split, quoted, glob, home)', () => {
    assert.equal(deny('rm -rf /'), 'rm-root')
    assert.equal(deny('rm -fr /'), 'rm-root')
    assert.equal(deny('rm -rf "/"'), 'rm-root')
    assert.equal(deny('rm -rf /*'), 'rm-root')
    assert.equal(deny('rm -rf ~'), 'rm-root')
    assert.equal(deny('rm -rf $HOME'), 'rm-root')
    assert.equal(deny('rm -r -f /'), 'rm-root-split-flags')
    assert.equal(deny('rm -f -r /'), 'rm-root-split-flags')
    assert.notEqual(deny('sudo rm -rf --no-preserve-root /'), undefined) // either rm-root or rm-no-preserve-root
  })
  test('guard: shutdown family denied (command position only)', () => {
    assert.equal(deny('shutdown -h now'), 'shutdown-family')
    assert.equal(deny('sudo reboot'), 'shutdown-family')
    assert.equal(deny('echo done; reboot'), 'shutdown-family')
    assert.equal(deny('init 0'), 'shutdown-family')
    assert.equal(deny('systemctl poweroff'), 'shutdown-family')
  })
  test('guard: chmod -R 777 / denied', () => {
    assert.equal(deny('chmod -R 777 /'), 'chmod-777-root')
  })

  test('guard: ordinary commands pass (no false positives)', () => {
    allow('ls -la /')
    allow('rm -rf /tmp/build')
    allow('rm -rf ~/projects/node_modules')
    allow('rm -rf ./dist')
    allow('dd if=/dev/sda of=/tmp/disk.img bs=4M') // reading FROM the device
    allow('echo hi > /dev/null')
    allow('head -c 16 /dev/urandom | xxd')
    allow('echo "the server will reboot tomorrow morning"') // prose, not command position
    allow('grep -rn reboot src/')
    allow('chmod -R 777 ./site')
    allow('mkdir -p ~/.config/newdir')
    allow('git reset --hard && git clean -fd')
    allow('shutdown_check.py --list') // \b requires command-position separators
  })

  test('guard: extra custom pattern compiles and matches', () => {
    const custom = compilePatterns({ useDefaults: false, extra: ['\\bgit\\s+push\\s+--force'] })
    assert.equal(matchGuard('git push --force origin main', custom)?.name.startsWith('custom:'), true)
    assert.equal(matchGuard('git status', custom), undefined)
  })
  test('guard: invalid custom pattern is skipped, not fatal', () => {
    const custom = compilePatterns({ useDefaults: false, extra: ['([unclosed'] })
    assert.equal(matchGuard('anything', custom), undefined)
  })

  // -- path protection --------------------------------------------------------
  const home = os.homedir()
  const protectedPaths = ['~/.ssh', '/etc'].map((entry) => expandPath(entry, { home }))
  test('expandPath: ~ expansion and cwd resolution', () => {
    assert.equal(expandPath('~', { home }), home)
    assert.equal(expandPath('~/.ssh', { home }), path.join(home, '.ssh'))
    assert.equal(expandPath('rel/x', { cwd: '/w' }), path.normalize('/w/rel/x'))
    assert.equal(expandPath('/abs'), '/abs')
  })
  test('protected-path containment is prefix-exact', () => {
    assert.equal(isUnderProtectedPath(path.join(home, '.ssh'), protectedPaths), path.join(home, '.ssh'))
    assert.equal(isUnderProtectedPath(path.join(home, '.ssh', 'authorized_keys'), protectedPaths), path.join(home, '.ssh'))
    assert.equal(isUnderProtectedPath(path.join(home, '.sshx'), protectedPaths), undefined) // sibling, not child
    assert.equal(isUnderProtectedPath('/etc/passwd', protectedPaths), '/etc')
    assert.equal(isUnderProtectedPath('/etcetera/x', protectedPaths), undefined)
    assert.equal(isUnderProtectedPath('/home/x', protectedPaths), undefined)
  })

  // -- email message ------------------------------------------------------------
  test('buildEmailMessage: headers and dot-stuffing', () => {
    const message = buildEmailMessage({ from: 'a@x.com', to: 'b@y.com', subject: 's', text: 'line1\n.secret\nend', date: new Date(0) })
    assert.match(message, /^From: a@x\.com\r\n/)
    assert.match(message, /^Subject: s\r\n/m)
    assert.match(message, /charset=utf-8/)
    assert.match(message, /\r\n\r\nline1\r\n\.\.secret\r\nend\r\n$/)
  })

  // -- fake SMTP dialogue ---------------------------------------------------------
  await test('sendEmail: full plaintext SMTP dialogue against a fake server', async () => {
    let captured = ''
    const server = net.createServer((socket) => {
      socket.write('220 fake.local ESMTP\r\n')
      let sawData = false
      let buffer = ''
      socket.on('data', (chunk) => {
        buffer += chunk
        for (;;) {
          const nl = buffer.indexOf('\r\n')
          if (nl === -1) return
          const line = buffer.slice(0, nl)
          buffer = buffer.slice(nl + 2)
          if (sawData) {
            if (line === '.') {
              sawData = false
              socket.write('250 queued as OK1\r\n')
            }
            continue
          }
          if (/^EHLO/i.test(line)) {
            socket.write('250-fake.local\r\n250-8BITMIME\r\n250 SIZE 10240000\r\n')
          } else if (/^AUTH PLAIN /i.test(line)) {
            socket.write('235 ok\r\n')
          } else if (/^MAIL FROM/i.test(line)) {
            socket.write('250 ok\r\n')
          } else if (/^RCPT TO/i.test(line)) {
            socket.write('250 ok\r\n')
          } else if (/^DATA/i.test(line)) {
            sawData = true
            socket.write('354 go\r\n')
          } else if (/^QUIT/i.test(line)) {
            socket.write('221 bye\r\n')
            socket.end()
          } else {
            socket.write('250 ok\r\n')
          }
        }
      })
    })
    // capture the raw client payload from the socket pair
    server.on('connection', (socket) => {
      const chunks = []
      socket.on('data', (chunk) => chunks.push(chunk))
      socket.on('close', () => {
        captured = Buffer.concat(chunks).toString('utf8')
      })
    })
    await new Promise((r) => server.listen(0, '127.0.0.1', r))
    const port = server.address().port
    await sendEmail(
      { host: '127.0.0.1', port, secure: false, user: 'u@example.com', pass: 'p', from: 'u@example.com', to: 'dest@example.com' },
      '[dsh yolo] armed',
      'event: armed\nsession: s1',
    )
    await new Promise((r) => setTimeout(r, 100))
    server.close()
    await new Promise((r) => server.on('close', r))
    assert.match(captured, /EHLO dsh-yolo/)
    assert.match(captured, /AUTH PLAIN /)
    assert.match(captured, /MAIL FROM:<u@example\.com>/)
    assert.match(captured, /RCPT TO:<dest@example\.com>/)
    assert.match(captured, /Subject: \[dsh yolo\] armed/)
    assert.match(captured, /event: armed/)
  })

  console.log(`\n${passed} passed, ${failed} failed`)
  process.exit(failed === 0 ? 0 : 1)
})()
