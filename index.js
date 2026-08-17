#!/usr/bin/env node
// htb-monitor — single-console live visibility for the local Kali box.
// Panels: VPN tunnel status/IP, CPU, memory, VPN bandwidth, stable TCP/UDP
// sessions, packet-derived flows, and every command exec'd in ANY shell.
//
// Run:  node index.js           (spawns bpftrace + `ss -p` via sudo)
// Quit: q / Esc / Ctrl-C
//
// Resource model (this dashboard is meant to run for days):
//   * All state that could grow with time/traffic is bounded — charts use
//     fixed-size ring buffers, the command pane has a scrollback cap, and the
//     two Maps (ancCache, spinWatch) are actively swept/evicted (see below).
//   * /proc is read once per source per tick; the only spawned processes are
//     the privileged pollers (ss, ip, ps) and the long-lived bpftrace trace,
//     which is auto-restarted if it dies.
//   * Constant facts (username, hostname) are resolved once at startup.
import fs from 'node:fs';
import os from 'node:os';
import http from 'node:http';
import { spawn, execFile, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import blessed from 'blessed';
import contrib from 'blessed-contrib';
import { buildArt, deriveState } from './art.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IFACE_OVERRIDE = process.env.HTB_IFACE || null; // force a tun iface name
const LOG_DIR = path.join(__dirname, 'logs');
const ERROR_LOG_PATH = path.join(LOG_DIR, 'runtime-errors.log');
const USER = os.userInfo().username;                 // constant for the process
const HOST = os.hostname();                          // lifetime — resolve once
const SELF_REFRESH_MS = 60 * 60_000;                // refresh monitor, never host

// ---------------------------------------------------------------- helpers
let uiErrorLog = null;
const runtimeErrSeen = new Map();
const ERR_REPEAT_MS = 60_000;

function errText(err) {
  if (err instanceof Error) return err.stack || err.message;
  return typeof err === 'string' ? err : JSON.stringify(err);
}

// Values arriving from execve/ss are untrusted terminal text.  Blessed parses
// braces as formatting tags, so a shell command containing e.g. `{foo}` can
// make its parser throw while repainting the dashboard.
const escapeBlessed = (value) => blessed.escape(String(value ?? ''));

function logRuntimeError(source, err, { ui = true } = {}) {
  const text = errText(err);
  const key = `${source}\t${text.split('\n')[0]}`;
  const now = Date.now();
  if (now - (runtimeErrSeen.get(key) || 0) < ERR_REPEAT_MS) return;
  runtimeErrSeen.set(key, now);
  if (runtimeErrSeen.size > 1000) {
    for (const [k, ts] of runtimeErrSeen) {
      if (now - ts > ERR_REPEAT_MS) runtimeErrSeen.delete(k);
      if (runtimeErrSeen.size <= 1000) break;
    }
    while (runtimeErrSeen.size > 1000) {
      runtimeErrSeen.delete(runtimeErrSeen.keys().next().value);
    }
  }

  const line = `[${new Date(now).toISOString()}] ${source}\n${text}\n\n`;
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    try {
      if (fs.existsSync(ERROR_LOG_PATH) && fs.statSync(ERROR_LOG_PATH).size > 10 * 1024 * 1024) {
        fs.renameSync(ERROR_LOG_PATH, `${ERROR_LOG_PATH}.1`);
      }
    } catch {}
    fs.appendFileSync(ERROR_LOG_PATH, line);
  } catch {}

  if (ui && uiErrorLog) {
    try {
      uiErrorLog.log(`{red-fg}[error] ${source}: ${text.split('\n')[0]}{/}`);
      screen.render();
    } catch {}
  }
}

function guardedInterval(source, fn, ms) {
  const run = () => {
    try { fn(); } catch (err) { logRuntimeError(source, err); }
  };
  const t = setInterval(run, ms);
  t.run = run;
  return t;
}

function guardedAsyncInterval(source, fn, ms) {
  let running = false;
  const run = async () => {
    if (running) {
      logRuntimeError(source, new Error(`skipped overlapping ${source} run`), { ui: false });
      return;
    }
    running = true;
    try { await fn(); } catch (err) { logRuntimeError(source, err); }
    finally { running = false; }
  };
  const t = setInterval(run, ms);
  t.run = run;
  return t;
}

const readProc = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
function monitoredExecFile(cmd, args, opts, callback) {
  const child = execFile(cmd, args, opts, callback);
  rememberMonitorPid(child.pid);
  return child;
}

function monitoredSpawn(cmd, args, opts) {
  const child = spawn(cmd, args, opts);
  rememberMonitorPid(child.pid);
  return child;
}

const sh = (cmd, args, opts = {}) => new Promise((res) =>
  monitoredExecFile(cmd, args, { timeout: 4000, maxBuffer: 1 << 20, ...opts }, (e, out) => res(e ? '' : out)));
const shChecked = (cmd, args, opts = {}) => new Promise((resolve, reject) =>
  monitoredExecFile(cmd, args, { timeout: 4000, maxBuffer: 1 << 20, ...opts }, (error, stdout = '', stderr = '') => {
    if (error) reject(new Error((stderr || error.message || `${cmd} failed`).trim()));
    else resolve(stdout);
  }));

// Pick the VPN interface: env override, else first up tun*/tap* in /proc/net/dev.
// Accepts a pre-read snapshot so a tick can read /proc/net/dev once and share it
// between detection and byte-counter parsing.
function detectTunIface(netdev = readProc('/proc/net/dev')) {
  if (IFACE_OVERRIDE) return IFACE_OVERRIDE;
  for (const line of netdev.split('\n')) {
    const name = line.split(':')[0]?.trim();
    if (name && /^(tun|tap)\d*/.test(name)) return name;
  }
  return null;
}

// Pick the primary LAN/egress interface (eth*/en*/wl*) and skip lo, the VPN
// tun/tap, and docker/veth/bridge virtuals. Same pre-read-snapshot contract as
// detectTunIface so a tick can share one /proc/net/dev read.
function detectLanIface(netdev = readProc('/proc/net/dev')) {
  for (const line of netdev.split('\n')) {
    const name = line.split(':')[0]?.trim();
    if (name && /^(eth|en|ens|eno|enp|wl)\w*\d/.test(name)) return name;
  }
  return null;
}

// Parse `ip -4 route show table main` into the small subset needed by the
// network panel. Keep every route (including default, connected, link-down,
// and special route types) so the panel is an honest view of the main table.
function parseRoutes(raw) {
  const specialTypes = new Set(['blackhole', 'unreachable', 'prohibit', 'throw']);
  const routes = [];
  for (const line of raw.split('\n')) {
    const fields = line.trim().split(/\s+/);
    if (!fields[0]) continue;
    const special = specialTypes.has(fields[0]) ? fields.shift() : '';
    const destination = fields.shift();
    if (!destination) continue;
    const valueAfter = (key) => {
      const i = fields.indexOf(key);
      return i >= 0 ? fields[i + 1] || '' : '';
    };
    routes.push({
      destination,
      via: valueAfter('via'),
      dev: valueAfter('dev'),
      src: valueAfter('src'),
      metric: valueAfter('metric'),
      special,
      linkdown: fields.includes('linkdown'),
    });
  }
  return routes;
}

// Show tunnel destinations first: those are usually the operator's current
// targets and must remain visible even when the route list is taller than the
// panel. Preserve kernel order inside each group.
function prioritizeRoutes(routes, tunnelIface) {
  return routes
    .map((route, order) => ({ route, order }))
    .sort((a, b) => {
      const rank = ({ route }) => route.dev === tunnelIface ? 0
        : route.destination === 'default' ? 2 : 1;
      return rank(a) - rank(b) || a.order - b.order;
    })
    .map(({ route }) => route);
}

function renderRoute(route, width, tunnelIface) {
  const color = route.dev === tunnelIface ? 'cyan' : route.linkdown ? 'red'
    : route.destination === 'default' ? 'yellow' : 'white';
  const destination = route.special
    ? `${route.special} ${route.destination}` : route.destination;
  const nextHop = route.via || route.dev || '—';
  let suffix = route.via && route.dev ? ` via ${route.via} · ${route.dev}`
    : route.via ? ` via ${route.via}`
      : route.dev ? ` dev ${route.dev}` : '';
  if (route.linkdown) suffix += ' DOWN';

  const innerW = Math.max(8, width);
  let text = `${destination}${suffix}`;
  if (text.length > innerW) text = `${destination} → ${nextHop}`;
  if (text.length > innerW && route.dev && nextHop !== route.dev) {
    text = `${destination} → ${route.dev}`;
  }
  return `{${color}-fg}${fitCell(text, innerW)}{/}`;
}

// GET a small JSON body from a loopback service (hexstrike /health). Loopback
// only + short timeout + capped body — never reaches off-box. Resolves the
// parsed object, or null on any error/timeout/non-200/parse failure.
function httpGetJson(port, urlPath, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: urlPath, timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return resolve(null); }
      let data = '';
      res.on('data', (c) => { data += c; if (data.length > 1 << 20) req.destroy(); });
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

// /proc/net/dev counters for one iface → bytes + packets, rx/tx.
// Takes an optional pre-read snapshot (see detectTunIface) to avoid a 2nd read.
function ifaceStats(iface, netdev = readProc('/proc/net/dev')) {
  for (const line of netdev.split('\n')) {
    const [name, rest] = line.split(':');
    if (name?.trim() === iface && rest) {
      const f = rest.trim().split(/\s+/);
      return { rx: +f[0], rxp: +f[1], tx: +f[8], txp: +f[9] };
    }
  }
  return null;
}

// host part of an "addr:port" socket field (handles [v6]:port and *:port)
function hostOf(s) {
  const i = s.lastIndexOf(':');
  return (i < 0 ? s : s.slice(0, i)).replace(/[[\]]/g, '');
}
const HTB_NET = /^(10\.10\.|10\.129\.)/; // HTB lab + tun ranges

// Truncate a cell to fit a column, keeping the :port suffix when possible
// and marking the cut with an ellipsis (mostly matters for long IPv6 addrs).
function fitCell(s, w) {
  if (s.length <= w) return s;
  const m = s.match(/^(\[.*\]|[^:]*):(\d+|\*)$/);   // host:port  (incl. [v6]:port)
  if (m) {
    const port = ':' + m[2];
    const hostRoom = w - port.length - 1;
    if (hostRoom >= 4) return m[1].slice(0, hostRoom) + '…' + port;
  }
  return s.slice(0, w - 1) + '…';
}

// uid → username, resolved once from /etc/passwd (root is always 0; ss omits
// the uid: field for root-owned sockets, so a missing field maps back here to 0).
const uidName = (() => {
  const map = new Map([[0, 'root']]);
  for (const line of readProc('/etc/passwd').split('\n')) {
    const f = line.split(':');
    if (f.length > 2 && f[2] !== '') map.set(+f[2], f[0]);
  }
  return map;
})();
const userOf = (uid) => uidName.get(uid) || `uid${uid}`;

// Classify a listening socket's bind address by exposure — drives its color in
// the sessions tree so a world-open port reads red at a glance.
function bindScope(host) {
  if (host === '0.0.0.0' || host === '*' || host === '::') return { fg: 'red', label: 'WORLD' };
  if (host === '127.0.0.1' || host === '::1') return { fg: 'green', label: 'local' };
  return { fg: 'yellow', label: host };
}
// Color a peer address by who it is: HTB/lab magenta, loopback gray, else white.
function peerColor(host) {
  if (HTB_NET.test(host)) return 'magenta';
  if (host === '127.0.0.1' || host === '::1') return 'gray';
  return 'white';
}

// One listening-socket snapshot → Map keyed by "proto/port". v4+v6 rows for the
// same service merge (their bind hosts collect into `binds`). Needs sudo -p for
// the process, -e for the owning uid.
async function collectListening() {
  const out = await sh('sudo', ['-n', 'ss', '-nltupe']);
  const svc = new Map();
  for (const line of out.split('\n').slice(1)) {
    const t = line.trim();
    if (!t) continue;
    const f = t.split(/\s+/);
    // Netid State Recv-Q Send-Q Local Peer Process...
    if (f.length < 6) continue;
    const proto = f[0], local = f[4];
    const host = hostOf(local);
    const port = local.slice(local.lastIndexOf(':') + 1);
    const pm = t.match(/"([^"]+)",pid=(\d+)/);
    const uidm = t.match(/\buid:(\d+)/);
    const key = `${proto}/${port}`;
    let e = svc.get(key);
    if (!e) { e = { proto, port, binds: new Set(), proc: pm?.[1] || '?', pid: pm?.[2] || '', uid: uidm ? +uidm[1] : 0, peers: [] }; svc.set(key, e); }
    e.binds.add(host);
  }
  return svc;
}

// ALL non-listening TCP/UDP conns → { conns:[{ proto, state, local, peer,
// lport, proc, pid }], truncated }. No state filter means a scan's SYN-SENT /
// TIME-WAIT sockets show up too — `state
// established` hid exactly the traffic worth watching during a scan.
//
// A wide connect scan can open hundreds of thousands of sockets; enumerating
// and buffering all of them would blow the buffer AND stall ss past our
// timeout, returning nothing right when you most want to see the scan. So we
// bound it at the source: `ss | head -n CONN_CAP` makes head close the pipe
// after CONN_CAP rows, ss takes SIGPIPE and stops early — output and runtime
// both bounded. Hitting the cap means "sampled", which is honest; an empty
// result (sudo/other failure) is NOT flagged as truncation.
const CONN_CAP = 4000;
async function collectConnections() {
  const out = await shChecked('sudo', ['-n', 'sh', '-c', `ss -H -tunp | head -n ${CONN_CAP + 1}`],
    { timeout: 6000, maxBuffer: 8 << 20 });
  const conns = [];
  let rows = 0;
  for (const line of out.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    rows++;
    const f = t.split(/\s+/);
    // Netid State Recv-Q Send-Q Local Peer Process
    if (f.length < 6) continue;
    const proto = f[0], state = f[1];
    if (state === 'LISTEN') continue;   // listeners come from collectListening
    const local = f[4], peer = f[5];
    if (!local.includes(':') || !peer.includes(':')) continue;
    const pm = t.match(/"([^"]+)",pid=(\d+)/);
    conns.push({ proto, state, local, peer, lport: local.slice(local.lastIndexOf(':') + 1), proc: pm?.[1] || '', pid: pm?.[2] || '' });
  }
  return { conns, truncated: rows >= CONN_CAP };
}

// Classify a command by walking its parent chain (/proc) up to PID 1:
//   'mine'      — inside this monitor's own process tree (ss/bpftrace/ip polls)
//   'hexstrike' — descends from the HexStrike server/agent
//   'ssh'       — descends from an sshd session (interactive remote shell)
//   'xfce-panel' — descends from xfce4-panel (desktop launcher/plugin noise)
//   'other'     — local desktop shells, daemons, cron, etc.
// 'mine' wins so the dashboard never shows the noise it generates itself.
const MY_PID = process.pid;
// Ancestor-classification cache: startPid -> { cat, t }. Without eviction this
// would grow one entry per unique PID ever seen — an unbounded leak over a
// multi-day run as PIDs churn. Entries are treated as stale after ANC_TTL and
// physically removed by the periodic sweep (sweepAncCache); ANC_MAX is a hard
// backstop against a burst filling the map faster than the sweep drains it.
const ANC_TTL = 8000;   // ms — cached classification considered fresh
const ANC_MAX = 4096;   // hard cap on live entries between sweeps
const ancCache = new Map();

// Explicitly track this monitor's exec tree. /proc ancestry is normally enough,
// but very short-lived helpers can exit before the bpftrace event reaches Node.
// Remembering observed parent/child links closes that race. Linux start times
// prevent a recycled PID from being mistaken for an old monitor descendant.
const MONITOR_PID_GRACE_MS = 60_000;
const MONITOR_PID_MAX = 4096;
const monitorPids = new Map(); // pid -> { start: /proc starttime|null, seen: ms }

function procStartTime(pid) {
  const stat = readProc(`/proc/${pid}/stat`);
  const close = stat.lastIndexOf(')');
  if (close < 0) return null;
  // Fields after "comm" begin at field 3 (state); starttime is field 22.
  return stat.slice(close + 2).trim().split(/\s+/)[19] || null;
}

function rememberMonitorPid(pid, now = Date.now()) {
  if (!Number.isInteger(pid) || pid <= 0) return;
  monitorPids.delete(pid); // refresh insertion order for bounded eviction
  monitorPids.set(pid, { start: procStartTime(pid), seen: now });
  while (monitorPids.size > MONITOR_PID_MAX) {
    const oldest = monitorPids.keys().next().value;
    if (oldest === MY_PID) {
      const self = monitorPids.get(oldest);
      monitorPids.delete(oldest);
      monitorPids.set(oldest, self);
      continue;
    }
    monitorPids.delete(oldest);
  }
}

function isMonitorPid(pid, now = Date.now()) {
  if (pid === MY_PID) return true;
  const known = monitorPids.get(pid);
  if (!known) return false;
  const currentStart = procStartTime(pid);
  if (known.start && currentStart && known.start !== currentStart) {
    monitorPids.delete(pid);
    return false;
  }
  if (currentStart) {
    known.start ||= currentStart;
    known.seen = now;
    return true;
  }
  if (now - known.seen <= MONITOR_PID_GRACE_MS) return true;
  monitorPids.delete(pid);
  return false;
}

function classifyExecOrigin(execPid, parentPid, comm) {
  if (execPid === MY_PID || isMonitorPid(execPid) || parentPid === MY_PID || isMonitorPid(parentPid)) {
    rememberMonitorPid(execPid);
    return 'mine';
  }
  const origin = comm === 'xfce4-panel' ? 'xfce-panel' : classifyOrigin(parentPid);
  if (origin === 'mine') rememberMonitorPid(execPid);
  return origin;
}

rememberMonitorPid(MY_PID);

function classifyOrigin(startPid) {
  const cached = ancCache.get(startPid);
  if (cached && Date.now() - cached.t < ANC_TTL) return cached.cat;
  let pid = startPid, depth = 0, ssh = false, hex = false, panel = false, mine = false;
  while (pid > 1 && depth++ < 40) {
    if (pid === MY_PID) { mine = true; break; }
    const stat = readProc(`/proc/${pid}/stat`);
    if (!stat) break;
    const close = stat.lastIndexOf(')');
    if (close < 0) break;
    const comm = stat.slice(stat.indexOf('(') + 1, close);
    const parent = parseInt(stat.slice(close + 2).split(' ')[1], 10);
    if (/^sshd/.test(comm)) ssh = true;
    if (comm === 'xfce4-panel') panel = true;
    if (/hexstrike/i.test(readProc(`/proc/${pid}/cmdline`).replace(/\0/g, ' '))) hex = true;
    if (!parent || parent === pid) break;
    pid = parent;
  }
  const cat = mine ? 'mine' : hex ? 'hexstrike' : ssh ? 'ssh' : panel ? 'xfce-panel' : 'other';
  ancCache.set(startPid, { cat, t: Date.now() });
  return cat;
}

// Drop expired ancestor-cache entries, then hard-cap the survivors. Map keeps
// insertion order, so deleting from the front evicts the oldest keys first.
// Runs on its own low-frequency timer (ancSweepTimer) — the exec path stays
// allocation-light and never has to walk the whole map itself.
function sweepAncCache() {
  const now = Date.now();
  for (const [pid, v] of ancCache) if (now - v.t > ANC_TTL) ancCache.delete(pid);
  if (ancCache.size > ANC_MAX) {
    let excess = ancCache.size - ANC_MAX;
    for (const k of ancCache.keys()) { if (excess-- <= 0) break; ancCache.delete(k); }
  }
}

function sweepMonitorPids() {
  const now = Date.now();
  for (const [pid, known] of monitorPids) {
    if (pid === MY_PID) continue;
    const currentStart = procStartTime(pid);
    if (currentStart && known.start && currentStart !== known.start) monitorPids.delete(pid);
    else if (currentStart) { known.start ||= currentStart; known.seen = now; }
    else if (now - known.seen > MONITOR_PID_GRACE_MS) monitorPids.delete(pid);
  }
}

// Bucket a command into an offensive-tooling category by tool name / argv.
// First match wins, so the order encodes priority (cracking before AD, etc).
const CATEGORIES = [
  ['creds',   'yellow',  /\b(hydra|medusa|john|hashcat|patator|crowbar|hashid|ophcrack|crack|cewl)\b/],
  ['ad',      'magenta', /\b(impacket|smbclient|smbmap|rpcclient|ldapsearch|ldapdomaindump|bloodhound|sharphound|evil-?winrm|enum4linux|nbtscan|crackmapexec|netexec|nxc|kerbrute|secretsdump|getnpusers|getuserspns|psexec|wmiexec|smbexec|atexec|responder|samrdump|ticketer|getuser)\b/i],
  ['web',     'blue',    /\b(gobuster|ffuf|feroxbuster|dirb|dirsearch|nikto|wpscan|katana|nuclei|sqlmap|wfuzz|whatweb|gau|waybackurls|arjun|dalfox|xsser|xsstrike|commix|httpx|hakrawler|paramspider|curl|wget|burp|zap)\b/],
  ['recon',   'cyan',    /\b(nmap|masscan|rustscan|autorecon|subfinder|amass|fierce|dnsenum|dnsrecon|fping|theharvester|recon-ng|spiderfoot|sherlock|shodan|netdiscover|arp-?scan|traceroute|whois|ping|dig|host|nslookup)\b/],
  ['exploit', 'red',     /\b(msfconsole|msfvenom|metasploit|searchsploit|ropgadget|one_gadget|gdb|radare2|objdump|checksec|pwntools|sliver|havoc|beef|exploit)\b/],
  ['shell',   'green',   /\b(bash|sh|zsh|dash|nc|ncat|socat|python3?|perl|ruby|php|ssh|scp|whoami|id|uname|cat|ls|sudo|su|chmod|chown|find|grep|awk|sed|env|which|ps|kill|mkdir|cp|mv|tmux|vim|nano|tee|sort|cut)\b/],
];
function categorize(comm, argv) {
  const s = `${comm} ${argv}`.toLowerCase();
  for (const [cat, , re] of CATEGORIES) if (re.test(s)) return cat;
  return 'other';
}
const CAT_COLOR = Object.fromEntries(CATEGORIES.map(([c, col]) => [c, col]).concat([['other', 'gray']]));
// Display order + an emoji per category for the activity strip. Order follows a
// rough attack progression so the icons sit in a stable, learnable position
// (they don't reshuffle as counts change). Emoji require fullUnicode on the
// screen (set above) — without it blessed renders them as '?'. Each row leads
// with exactly one (double-width) emoji, so the label/count columns stay aligned.
const CATS = ['recon', 'web', 'creds', 'ad', 'exploit', 'shell', 'other'];
const CAT_ICON = {
  recon: '📡', web: '🌐', creds: '🔑', ad: '🏰',
  exploit: '💥', shell: '🐚', other: '📦',
};

// Per-core {idle,total} snapshots from /proc/stat (index = core number)
function cpuCores() {
  const cores = [];
  for (const line of readProc('/proc/stat').split('\n')) {
    const m = line.match(/^cpu(\d+)\s+(.*)/);
    if (!m) continue;
    const f = m[2].trim().split(/\s+/).map(Number);
    cores[+m[1]] = { idle: f[3] + (f[4] || 0), total: f.reduce((a, b) => a + b, 0) };
  }
  return cores;
}

// htop-style colored bar for a 0..100 percentage
function cpuBar(pct, width) {
  const safeWidth = Math.max(0, Math.floor(Number.isFinite(width) ? width : 0));
  const safePct = Math.max(0, Math.min(100, Number.isFinite(pct) ? pct : 0));
  const filled = Math.max(0, Math.min(safeWidth, Math.round((safePct / 100) * safeWidth)));
  const col = safePct < 50 ? 'green' : safePct < 85 ? 'yellow' : 'red';
  return `{${col}-fg}${'|'.repeat(filled)}{/}${' '.repeat(safeWidth - filled)}`;
}

// Like cpuBar, but also draws a red high-water tick (┃) at `peak` — the max
// utilization this core hit over the trailing window (see CPU_HIST). Lets you
// see, at a glance, how hard a core spiked in the last few minutes even if it's
// idle right now. The tick overwrites whatever cell it lands on (fill or track)
// and is suppressed below 3% so idle cores don't wear a permanent red pip.
function cpuBarPeak(pct, peak, width) {
  const safeWidth = Math.max(0, Math.floor(Number.isFinite(width) ? width : 0));
  const safePct = Math.max(0, Math.min(100, Number.isFinite(pct) ? pct : 0));
  const safePeak = Math.max(0, Math.min(100, Number.isFinite(peak) ? peak : 0));
  const col = safePct < 50 ? 'green' : safePct < 85 ? 'yellow' : 'red';
  const filled = Math.max(0, Math.min(safeWidth, Math.round((safePct / 100) * safeWidth)));
  const cells = new Array(safeWidth).fill(' ');
  for (let x = 0; x < filled; x++) cells[x] = `{${col}-fg}|{/}`;
  if (safePeak >= 3 && safeWidth > 0) {
    const pos = Math.max(0, Math.min(safeWidth - 1, Math.round((safePeak / 100) * safeWidth) - 1));
    cells[pos] = '{red-fg}{bold}┃{/}';
  }
  return cells.join('');
}

function memUsage() {
  const m = {};
  for (const line of readProc('/proc/meminfo').split('\n')) {
    const [k, v] = line.split(':');
    if (v) m[k.trim()] = parseInt(v, 10); // kB
  }
  const total = m.MemTotal || 1;
  const avail = m.MemAvailable ?? ((m.MemFree || 0) + (m.Buffers || 0) + (m.Cached || 0));
  const used = Math.max(0, total - avail);
  const usedPct = Math.max(0, Math.min(100, Math.round((used / total) * 100)));
  return { usedPct, usedGB: (used / 1048576).toFixed(1), totalGB: (total / 1048576).toFixed(1) };
}

// Render a "top N processes" tile: one row per process with an adaptive
// name column, a proportional bar (normalized to the largest value shown),
// and a right-aligned value. Shared by the Top Mem and Top CPU tiles so they
// stay visually identical; each passes its own value accessor + formatter.
// Row count and column widths are derived from the box's current size so the
// tile fills whatever space the grid gives it (and reflows on resize).
function renderProcTile(box, procs, valueOf, fmtValue, barColor) {
  const rowN = Math.max(1, (box.height || 6) - 3);      // minus 2 border + header
  const safeMetric = (p) => {
    const n = valueOf(p);
    return Number.isFinite(n) ? n : 0;
  };
  const shown = [...procs].sort((a, b) => safeMetric(b) - safeMetric(a)).slice(0, rowN);
  const vals = shown.map(safeMetric);
  const maxV = vals.length ? Math.max(1e-9, ...vals) : 1;
  const innerW = Math.max(16, (box.width || 24) - 2);
  const valW = 6, gaps = 2;
  const nameW = Math.max(6, Math.min(14, innerW - valW - gaps - 4));
  const barW = Math.max(4, innerW - nameW - valW - gaps);
  let txt = '';
  for (const p of shown) {
    const safeValue = Math.max(0, safeMetric(p));
    const filled = Math.max(0, Math.min(barW, Math.round((safeValue / maxV) * barW)));
    txt += `{cyan-fg}${p.comm.slice(0, nameW).padEnd(nameW)}{/} `
      + `{${barColor}-fg}${'▮'.repeat(filled)}{/}${'·'.repeat(barW - filled)} `
      + `${fmtValue(p).padStart(valW)}\n`;
  }
  box.setContent(txt);
}

const fmtRate = (bps) => bps > 1048576 ? (bps / 1048576).toFixed(2) + ' MB/s'
  : bps > 1024 ? (bps / 1024).toFixed(1) + ' KB/s' : Math.round(bps) + ' B/s';
const fmtBytes = (b) => b > 1073741824 ? (b / 1073741824).toFixed(2) + ' GB'
  : b > 1048576 ? (b / 1048576).toFixed(1) + ' MB' : (b / 1024).toFixed(1) + ' KB';

// ---------------------------------------------------------------- UI layout
// fullUnicode: render astral-plane codepoints (emoji) — without it blessed
// replaces them with '?'. Needs a terminal with a color-emoji fallback font
// (NotoColorEmoji here); emoji are double-width, handled by blessed's width
// tables. The activity-strip layout leads every row with exactly one emoji so
// any width quirk shifts all rows equally and the columns stay aligned.
function requireInteractiveTerminal() {
  if (!process.stdin.isTTY || !process.stdout.isTTY || typeof process.stdin.setRawMode !== 'function') {
    console.error('htb-monitor needs an interactive terminal (TTY). Run it from a terminal, or use ssh -tt / tmux.');
    process.exit(2);
  }
  const wasRaw = process.stdin.isRaw;
  try {
    // Probe the PTY before Blessed installs listeners.  A detached SSH/PTY
    // can still report isTTY while setRawMode fails with EIO.
    process.stdin.setRawMode(true);
    if (!wasRaw) process.stdin.setRawMode(false);
  } catch (err) {
    console.error(`htb-monitor cannot access the terminal (${err.code || err.message}). Reconnect with ssh -tt or start it inside tmux.`);
    process.exit(2);
  }
}
requireInteractiveTerminal();
const screen = blessed.screen({ smartCSR: true, fullUnicode: true, title: 'htb-monitor' });
// Give the proportional grid every terminal line except the fixed status bar.
// A dedicated parent avoids percentage-based blank space on tall terminals and
// prevents the bottom widgets from being hidden beneath the status line.
const dashboard = blessed.box({
  parent: screen, top: 0, left: 0, width: '100%', height: '100%-1',
});
const grid = new contrib.grid({ rows: 24, cols: 12, screen: dashboard });
const neutralScrollbar = () => ({ ch: '│', style: { fg: 'white', bg: 'black' } });

// Top-left column (cols 0-3) split in two: Status banner over the CPU box.
const artBox = grid.set(0, 0, 5, 4, blessed.box, {
  label: ' Status ', tags: true, border: { type: 'line' },
  style: { border: { fg: 'green' } }, content: '',
});
const cpuBox = grid.set(5, 0, 5, 4, blessed.box, {
  label: ' CPU (per core) ', tags: true, mouse: true, keys: true, vi: true,
  scrollable: true, alwaysScroll: false, scrollback: 200,
  scrollbar: neutralScrollbar(), border: { type: 'line' },
  style: { border: { fg: 'green' } }, content: 'sampling…',
});
// Top-middle (cols 4-7): command-category stats over two equal process tiles.
// stacked over two side-by-side process tiles — top RSS (Top Mem) and top
// %CPU (Top CPU). The top row uses three balanced four-column sections.
const statsBox = grid.set(0, 4, 6, 4, blessed.box, {
  label: ' Command Stats ', tags: true, border: { type: 'line' },
  style: { border: { fg: 'yellow' } }, content: '',
});
const memProcBox = grid.set(6, 4, 4, 2, blessed.box, {
  label: ' Top Mem ', tags: true, border: { type: 'line' },
  style: { border: { fg: 'yellow' } }, content: '',
});
const cpuProcBox = grid.set(6, 6, 4, 2, blessed.box, {
  label: ' Top CPU ', tags: true, border: { type: 'line' },
  style: { border: { fg: 'yellow' } }, content: '',
});
const vpnBox = grid.set(0, 8, 10, 4, blessed.box, {
  label: ' VPN & Routes ', tags: true, mouse: true, keys: true, vi: true,
  scrollable: true, alwaysScroll: false, scrollback: 200,
  scrollbar: neutralScrollbar(),
  border: { type: 'line' },
  style: { border: { fg: 'white' }, fg: 'white' }, content: 'initializing…',
});
// Bottom: Sessions and packet-derived flows stay visible together in a
// horizontal split of the narrow network column; Commands remains wide.
// Sessions is a hand-rendered tree (not a table): listen ports grouped over
// the peers connected to them, plus an outbound group. A scrollable blessed.box
// gives full control over per-node color + folding text on every live refresh.
const sessBox = grid.set(10, 0, 7, 5, blessed.box, {
  label: ' Sessions ', tags: true, mouse: true, keys: true, vi: true,
  scrollable: true, alwaysScroll: false, scrollback: 1000,
  scrollbar: neutralScrollbar(),
  border: { type: 'line' }, style: { border: { fg: 'white' }, fg: 'white' },
});
const flowBox = grid.set(17, 0, 7, 5, blessed.box, {
  label: ' Packet Flows ', tags: true, mouse: true, keys: true, vi: true,
  scrollable: true, alwaysScroll: false, scrollback: 1000,
  scrollbar: neutralScrollbar(),
  border: { type: 'line' }, style: { border: { fg: 'yellow' }, fg: 'white' },
});
// blessed.log (not contrib.log): it auto-follows new output but pauses when
// you scroll up, and resumes when you scroll back to the bottom — built in.
const cmdLog = grid.set(10, 5, 14, 7, blessed.log, {
  label: ' Commands [all]  ↑↓/wheel scroll · End=live · a=hexstrike ', tags: true,
  mouse: true, keys: true, vi: true, scrollable: true, alwaysScroll: false,
  scrollback: 2000, scrollbar: neutralScrollbar(),
  border: { type: 'line' }, style: { border: { fg: 'red' }, fg: 'white' },
});
uiErrorLog = cmdLog;
// Status bar lives OUTSIDE the grid — the grid force-adds a border that
// would eat its single line. Anchor it to the bottom over the reserved row.
const statusBar = blessed.box({
  parent: screen, bottom: 0, left: 0, width: '100%', height: 1,
  tags: true, style: { fg: 'white', bg: 'blue' },
});

// contrib.grid expresses positions as percentages, whose independent rounding
// can leave a blank row or column at some terminal sizes. Resolve the intended
// proportions to shared integer boundaries so adjacent panels always meet and
// the dashboard consumes every cell above the status bar.
function layoutDashboard() {
  const width = Math.max(1, Number(dashboard.width) || screen.width || 1);
  const height = Math.max(1, Number(dashboard.height) || Math.max(1, screen.height - 1));
  const topBottom = Math.max(1, Math.min(height - 1, Math.round(height * 10 / 24)));
  const topHalf = Math.max(1, Math.min(topBottom - 1, Math.round(topBottom / 2)));
  const statsBottom = Math.max(1, Math.min(topBottom - 1, Math.round(topBottom * 6 / 10)));
  const firstThird = Math.round(width / 3);
  const secondThird = Math.round(width * 2 / 3);
  const bottomSplit = Math.round(width * 5 / 12);
  const bottomHalf = topBottom + Math.round((height - topBottom) / 2);

  const place = (widget, top, left, bottom, right) => {
    widget.top = top;
    widget.left = left;
    widget.height = Math.max(1, bottom - top);
    widget.width = Math.max(1, right - left);
  };

  place(artBox, 0, 0, topHalf, firstThird);
  place(cpuBox, topHalf, 0, topBottom, firstThird);
  place(statsBox, 0, firstThird, statsBottom, secondThird);
  const processSplit = firstThird + Math.round((secondThird - firstThird) / 2);
  place(memProcBox, statsBottom, firstThird, topBottom, processSplit);
  place(cpuProcBox, statsBottom, processSplit, topBottom, secondThird);
  place(vpnBox, 0, secondThird, topBottom, width);
  place(sessBox, topBottom, 0, bottomHalf, bottomSplit);
  place(flowBox, bottomHalf, 0, height, bottomSplit);
  place(cmdLog, topBottom, bottomSplit, height, width);
}
layoutDashboard();

let prevCores = cpuCores();
// Per-core ring of recent utilization samples → 5-minute high-water mark.
// 1 tick = 1s, so 300 samples ≈ 5 min. Bounded: coreHist[i] never exceeds
// CPU_HIST entries. Populated lazily as cores are first seen.
const CPU_HIST = 300;
const coreHist = [];
let prevNet = null;
let iface = detectTunIface();
let tunIP = null;            // current tunnel IP, for session filtering
let filterTunnel = false;    // press 'f' to show only tunnel sessions/flows (default: all)
let hexOnly = false;         // press 'a' to filter to only hexstrike execs (default: show all)
const CLOSED_SESSION_TTL_MS = 60_000;
const SESSION_HISTORY_MAX = 12_000;
const sessionHistory = new Map(); // local/peer -> active or recently closed
const FLOW_TTL_MS = 60_000;
const FLOW_MAX = 4096;
const flows = new Map();           // iface/proto/src/dst -> packet counters
let flowEvictionPending = false;
let flowCaptureStatus = 'starting';
let flowCaptureRestarts = 0;
let flowCaptureSignature = '';
let flowCaptureReconfigure = false;

// --- animated-status state (drives the ASCII art banner) ---
let frame = 0;               // animation frame counter
let lastHexTs = 0;           // last hexstrike exec (ms) → "attack"
let lastActTs = 0;           // last ssh exec (ms)       → "active"
let lastCmdText = '';        // most recent shown command, for the banner detail
let bwIntensity = 0;         // 0..1, current tunnel throughput → wave amplitude
// Rolling 1-hour command counts per category, kept as 60 one-minute buckets
// per category (constant memory — no per-event list to prune). The current
// minute is bucketMin % 60; advancing time clears the buckets we roll into
// (see rollBuckets). catLastTs drives the icon highlight: a category's glyph
// lights up for HL_MS after its most recent detection.
const HL_MS = 5000;          // icon stays lit this long after a detection
const BUCKET_MIN = 60;       // rolling window length, in one-minute buckets
const catBuckets = Object.fromEntries(CATS.map((c) => [c, new Array(BUCKET_MIN).fill(0)]));
const catLastTs = Object.fromEntries(CATS.map((c) => [c, 0]));
let bucketMin = Math.floor(Date.now() / 60000);   // absolute minute of newest bucket
let cmdTotal = 0;            // total non-self commands seen (session lifetime)

// Advance the minute-bucket ring to `nowMs`, zeroing every bucket we roll into
// so each holds exactly its minute's tally and the 60-bucket sum stays a true
// trailing hour. A gap larger than the window clears everything (all 60 slots
// are visited). Called from tick() (so idle categories decay) and per exec.
function rollBuckets(nowMs) {
  const cur = Math.floor(nowMs / 60000);
  if (cur === bucketMin) return;
  const advance = Math.min(BUCKET_MIN, cur - bucketMin);
  for (let k = 1; k <= advance; k++) {
    const idx = (bucketMin + k) % BUCKET_MIN;
    for (const c of CATS) catBuckets[c][idx] = 0;
  }
  bucketMin = cur;
}

// Write-buffered, rotation-aware exec log.
// Writes are batched every LOG_FLUSH_MS (not per-event) to avoid continuous
// VMDK write pressure in VMware. Rotation keeps the log under MAX_LOG_SIZE.
const MAX_LOG_SIZE  = 50 * 1024 * 1024; // 50 MB per file
const MAX_LOG_FILES = 3;
const LOG_FLUSH_MS  = 2000;
const LOG_PATH      = path.join(LOG_DIR, 'exec-history.log');

let execLogStream = null;
let logBuf = [];
let logBufBytes = 0;

function openLogStream() {
  execLogStream = fs.createWriteStream(LOG_PATH, { flags: 'a' });
  execLogStream.on('error', (err) => {
    logRuntimeError('exec-history log stream', err);
    try { execLogStream.end(); } catch {}
    execLogStream = null;
  });
}

function rotateLog() {
  if (execLogStream) { try { execLogStream.end(); } catch {} execLogStream = null; }
  for (let i = MAX_LOG_FILES - 1; i >= 1; i--) {
    try { fs.renameSync(`${LOG_PATH}.${i}`, `${LOG_PATH}.${i + 1}`); } catch {}
  }
  try { fs.renameSync(LOG_PATH, `${LOG_PATH}.1`); } catch {}
  openLogStream();
}

function flushLogBuf() {
  if (!logBuf.length) return;
  if (!execLogStream) {
    try { openLogStream(); } catch (err) { logRuntimeError('exec-history log reopen', err); return; }
  }
  const chunk = logBuf.join('');
  execLogStream.write(chunk, (err) => {
    if (err) logRuntimeError('exec-history log write', err);
  });
  logBuf = []; logBufBytes = 0;
  try { if (fs.statSync(LOG_PATH).size > MAX_LOG_SIZE) rotateLog(); } catch {}
}

fs.mkdirSync(LOG_DIR, { recursive: true });
openLogStream();
const logFlushTimer = guardedInterval('flushLogBuf', flushLogBuf, LOG_FLUSH_MS);

// ---------------------------------------------------------------- hexstrike watchdog
// Only kills hexstrike_mcp.py processes that are BOTH orphaned (PPID=1, meaning
// their Claude Code session already exited) AND CPU-spinning. A process with a
// live parent is doing real work and is never touched regardless of CPU usage.
// High-CPU processes with live parents get a visible warning only.
const WATCHDOG_MS        = 15_000;  // check interval
const ORPHAN_SPIN_THRESH = 50;      // % CPU — orphan spinning at this level = dead weight
const ORPHAN_KILL_MS     = 60_000;  // kill orphan after spinning this long (1 min grace)
const LIVE_WARN_THRESH   = 95;      // % CPU warn threshold for processes with live parents
const LIVE_WARN_MS       = 300_000; // only warn after 5 min sustained (legitimate work window)
const MAX_MCP_WARN       = 4;       // warn if more instances than this
const spinWatch          = new Map(); // pid → { firstSpinTs, orphan }
let wdKillCount          = 0;
let wdLastCountAlert     = 0;

// --- hexstrike MCP service health (shown in the Status banner) ---
// Server = the loopback HTTP API on :8888 (/health); mcp bridge count is set by
// the watchdog below (it already scans hexstrike_mcp.py). Polled on HEX_MS.
const HEX_PORT   = 8888;
const HEX_MS     = 5000;
let hexServerUp  = false;
let hexTools     = 0;
let hexMcpCount  = 0;   // written by hexstrikeWatchdog()
async function hexHealthTick() {
  const j = await httpGetJson(HEX_PORT, '/health');
  if (j) {
    hexServerUp = true;
    let avail = 0;
    const cs = j.category_stats || {};
    for (const k in cs) avail += cs[k]?.available || 0;
    hexTools = avail || j.total_tools_available || 0;
  } else {
    hexServerUp = false;
    hexTools = 0;
  }
}

async function hexstrikeWatchdog() {
  const raw = await sh('sh', ['-c',
    "ps --no-headers -eo 'pid,ppid,%cpu,args' 2>/dev/null | grep hexstrike_mcp\\.py | grep -v grep"]);
  if (!raw.trim()) { spinWatch.clear(); hexMcpCount = 0; return; }

  const now   = Date.now();
  const seen  = new Set();
  const procs = [];

  for (const line of raw.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) continue;
    const pid   = parseInt(parts[0], 10);
    const ppid  = parseInt(parts[1], 10);
    const cpu   = parseFloat(parts[2]);
    if (isNaN(pid) || isNaN(cpu)) continue;
    const orphan = ppid === 1;
    seen.add(pid);
    procs.push({ pid, ppid, cpu, orphan });

    if (orphan && cpu >= ORPHAN_SPIN_THRESH) {
      // Orphan spinning: track and kill after grace period
      if (!spinWatch.has(pid)) spinWatch.set(pid, { firstSpinTs: now, orphan: true });
      const elapsed = now - spinWatch.get(pid).firstSpinTs;
      if (elapsed >= ORPHAN_KILL_MS) {
        cmdLog.log(`{red-fg}[watchdog] PID ${pid} orphaned + ${cpu.toFixed(0)}% CPU for ${Math.round(elapsed / 1000)}s — terminating{/}`);
        try { process.kill(pid, 'SIGTERM'); } catch {}
        const killPid = pid;
        setTimeout(() => { try { process.kill(killPid, 'SIGKILL'); } catch {} }, 5000);
        spinWatch.delete(pid);
        wdKillCount++;
        screen.render();
      }
    } else if (!orphan && cpu >= LIVE_WARN_THRESH) {
      // Live parent, very high CPU: track for warning only, never kill
      if (!spinWatch.has(pid)) spinWatch.set(pid, { firstSpinTs: now, orphan: false });
      const elapsed = now - spinWatch.get(pid).firstSpinTs;
      if (elapsed >= LIVE_WARN_MS) {
        cmdLog.log(`{yellow-fg}[watchdog] PID ${pid} (active session) ${cpu.toFixed(0)}% CPU for ${Math.round(elapsed / 60000)}min — monitoring (not killing){/}`);
        spinWatch.set(pid, { firstSpinTs: now, orphan: false }); // reset so we don't spam
        screen.render();
      }
    } else {
      spinWatch.delete(pid);
    }
  }

  hexMcpCount = procs.length;

  // Clean stale entries for dead processes
  for (const [pid] of spinWatch) { if (!seen.has(pid)) spinWatch.delete(pid); }

  // Warn when instance count is abnormally high (rate-limited to once per 2 min)
  if (procs.length > MAX_MCP_WARN && now - wdLastCountAlert > 120_000) {
    const orphans = procs.filter(p => p.orphan).length;
    cmdLog.log(`{yellow-fg}[watchdog] ${procs.length} hexstrike_mcp instances (${orphans} orphaned) — possible session leak{/}`);
    wdLastCountAlert = now;
    screen.render();
  }
}

const wdTimer = guardedAsyncInterval('hexstrikeWatchdog', hexstrikeWatchdog, WATCHDOG_MS);
wdTimer.run();

// ---------------------------------------------------------------- pollers
async function tick() {
  ensureFlowCaptureInterfaces();
  const netdev = readProc('/proc/net/dev');   // read once, reused below
  const currentIface = detectTunIface(netdev);
  iface = currentIface;

  // --- VPN status + addresses + IPv4 main routing table ---
  // Resolve the LAN interface's IPv4 too — it's the box's real network address
  // and is useful whether or not the tunnel is up.
  const lanIface = detectLanIface(netdev);
  const [lanAddrOut, tunAddrOut, routeOut] = await Promise.all([
    lanIface ? sh('ip', ['-o', '-4', 'addr', 'show', lanIface]) : Promise.resolve(''),
    currentIface ? sh('ip', ['-o', '-4', 'addr', 'show', currentIface]) : Promise.resolve(''),
    sh('ip', ['-4', 'route', 'show', 'table', 'main']),
  ]);
  const lanIP = lanAddrOut.match(/inet\s+([\d.]+)/)?.[1] || null;
  tunIP = tunAddrOut.match(/inet\s+([\d.]+)/)?.[1] || null;
  const routes = prioritizeRoutes(parseRoutes(routeOut), currentIface);
  const routeW = Math.max(8, (vpnBox.width || 32) - 4);
  const routeLines = routes.map((route) => renderRoute(route, routeW, currentIface));
  const lanLine = `${lanIface || 'LAN'} {bold}${lanIP || '—'}{/}`;
  if (currentIface) {
    vpnBox.style.border.fg = 'green';
  } else {
    vpnBox.style.border.fg = 'red';
  }

  // --- CPU (per core, htop-style, with a 5-min peak tick) ---
  const cores = cpuCores();
  // bar fills the box: inner width minus the "NN[...NNN%]" chrome (~9 chars)
  const W = Math.max(10, Math.min(60, (cpuBox.width || 30) - 11));
  let cpuTxt = '', sum = 0, peakMax = 0, coreCount = 0;
  for (let i = 0; i < cores.length; i++) {
    if (!cores[i]) continue;
    const p = prevCores[i];
    const dT = p ? cores[i].total - p.total : 0, dI = p ? cores[i].idle - p.idle : 0;
    const pct = dT > 0 ? Math.round((1 - dI / dT) * 100) : 0;
    sum += pct;
    coreCount++;
    // roll this core's 5-min sample ring and read its high-water mark
    const hist = coreHist[i] || (coreHist[i] = []);
    hist.push(pct);
    if (hist.length > CPU_HIST) hist.shift();
    const peak = Math.max(...hist);
    if (peak > peakMax) peakMax = peak;
    cpuTxt += `{bold}${String(i).padStart(2)}{/}[${cpuBarPeak(pct, peak, W)}${String(pct).padStart(3)}%]\n`;
  }
  prevCores = cores;
  const avg = coreCount ? Math.round(sum / coreCount) : 0;
  cpuBox.setContent(cpuTxt.trimEnd());
  cpuBox.setLabel(` CPU ${avg}% avg · peak5m ${peakMax}% · ${coreCount} cores · load ${os.loadavg()[0].toFixed(2)} `);

  // --- Memory ---
  const m = memUsage();

  // --- Status bar (host · clock · keys) ---
  const clock = new Date().toLocaleTimeString();
  statusBar.setContent(
    `{bold} ${USER}@${HOST}{/} {gray-fg}pid:${MY_PID}{/}  {bold}${clock}{/}` +
    `   {white-fg}q{/} quit · {white-fg}f{/} traffic · {white-fg}a{/} cmds` +
    `   traffic:{bold}${filterTunnel ? 'tunnel' : 'all'}{/} · cmds:{bold}${hexOnly ? 'hexstrike' : 'all'}{/}` +
    (wdKillCount ? `   {red-fg}⚠ watchdog kills: ${wdKillCount}{/}` : '') + ' ');

  // --- Command activity (icon lights up on live detection; count = last 1h) ---
  // Fixed category order → icons hold a stable, learnable position. Each row's
  // glyph "lights up" (colored background chip) for HL_MS after its category
  // last fired; the number is that category's rolling 1-hour count, with a bar
  // for quick visual comparison of what's most active.
  rollBuckets(Date.now());
  const nowMs = Date.now();
  const counts1h = Object.fromEntries(CATS.map((c) => [c, catBuckets[c].reduce((a, b) => a + b, 0)]));
  const maxN = Math.max(1, ...Object.values(counts1h));
  const sW = Math.max(6, Math.min(20, (statsBox.width || 24) - 20));
  let statsTxt = '', sum1h = 0;
  for (const cat of CATS) {
    const n = counts1h[cat]; sum1h += n;
    const col = CAT_COLOR[cat];
    const hot = nowMs - catLastTs[cat] < HL_MS;
    const chip = hot ? `{${col}-bg} ${CAT_ICON[cat]} {/}` : ` ${CAT_ICON[cat]} `;
    const label = hot ? `{${col}-fg}{bold}${cat.padEnd(7)}{/}` : `{gray-fg}${cat.padEnd(7)}{/}`;
    const filled = Math.round((n / maxN) * sW);
    const bar = `{${col}-fg}${'▮'.repeat(filled)}{/}${'·'.repeat(sW - filled)}`;
    const numCol = hot ? `{bold}{${col}-fg}` : n > 0 ? `{${col}-fg}` : '{gray-fg}';
    statsTxt += `${chip} ${label} ${bar} ${numCol}${String(n).padStart(4)}{/}\n`;
  }
  statsTxt += `\n{bold}Σ 1h ${sum1h}{/}  {gray-fg}· session ${cmdTotal}{/}`;
  statsBox.setLabel(' Command Activity (1h) ');
  statsBox.setContent(statsTxt);

  // --- Top processes by memory (RSS) and CPU (%CPU) ---
  // One `ps` snapshot feeds both tiles; each tile sorts + renders its own
  // metric. %CPU here is ps's lifetime-average per-process utilization (can
  // exceed 100% on multicore), matching how the watchdog reads it — a live
  // instantaneous figure would need cross-tick /proc sampling and a bounded
  // per-pid state map, which isn't worth it for an at-a-glance tile.
  const psOut = await sh('ps', ['-eo', 'rss=,pcpu=,comm=']);
  const procs = [];
  for (const line of psOut.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+([\d.]+)\s+(.+)$/);
    if (m) procs.push({ rss: +m[1], cpu: +m[2], comm: m[3].trim() });
  }
  renderProcTile(memProcBox, procs, (p) => p.rss,
    (p) => { const mb = p.rss / 1024; return mb >= 1024 ? `${(mb / 1024).toFixed(1)}G` : `${mb.toFixed(0)}M`; },
    'green');
  renderProcTile(cpuProcBox, procs, (p) => p.cpu,
    (p) => (p.cpu >= 10 ? p.cpu.toFixed(0) : p.cpu.toFixed(1)) + '%',
    'yellow');

  // --- Bandwidth + packet rate over tunnel ---
  const now = ifaceStats(currentIface, netdev);
  let dKB = 0, uKB = 0, dPPS = 0, uPPS = 0;
  if (now && prevNet && prevNet.iface === currentIface) {
    dKB = Math.max(0, (now.rx - prevNet.rx) / 1024);
    uKB = Math.max(0, (now.tx - prevNet.tx) / 1024);
    dPPS = Math.max(0, now.rxp - prevNet.rxp);
    uPPS = Math.max(0, now.txp - prevNet.txp);
  }
  bwIntensity = Math.min(1, (dKB + uKB) / 400);   // feeds the status art wave
  prevNet = now ? { ...now, iface: currentIface } : null;
  const vpnState = currentIface
    ? `{green-fg}{bold}● CONNECTED{/} ${currentIface} {bold}${tunIP || '—'}{/}`
    : '{red-fg}{bold}● DISCONNECTED{/} no tun/tap';
  const totals = prevNet
    ? `TOTAL ↓${fmtBytes(prevNet.rx)} · ↑${fmtBytes(prevNet.tx)}` : 'TOTAL —';
  vpnBox.setLabel(` VPN & Routes ${routes.length} · ↑↓ scroll `);
  vpnBox.setContent(
    `${vpnState}\n` +
    `${lanLine} · RAM ${m.usedPct}%\n` +
    `BW ↓${dKB.toFixed(1)} ↑${uKB.toFixed(1)} KB/s · ↓${dPPS} ↑${uPPS}pps\n` +
    `${totals}\n` +
    `{bold}DESTINATION → GATEWAY / INTERFACE{/}\n` +
    (routeLines.join('\n') || '{gray-fg}no IPv4 routes{/}'));

  // Sessions poll independently because `ss` can be slower during scans.
  // Packet aggregation is already in memory, so repainting it here is cheap.
  renderFlows();
  screen.render();
}

// Re-render the sessions tree and repaint. Its independent timer prevents a
// slow `ss` snapshot during a scan from delaying the rest of the dashboard.
async function refreshSessions() {
  await renderSessions();
  screen.render();
}

// TCP state -> short label + color. SYN-SENT (outbound half-open) is the tell
// of an active connect scan, so it gets a loud color; settled/teardown states
// are dimmed. Unknown states fall back to the raw label in gray.
const STATE_STYLE = {
  ESTAB: ['green', 'estab'], 'SYN-SENT': ['yellow', 'syn->'], 'SYN-RECV': ['yellow', 'syn<-'],
  'TIME-WAIT': ['gray', 'twait'], 'CLOSE-WAIT': ['gray', 'cwait'], 'FIN-WAIT-1': ['gray', 'fin1'],
  'FIN-WAIT-2': ['gray', 'fin2'], 'LAST-ACK': ['gray', 'lack'], CLOSING: ['gray', 'closing'],
};
const stateStyle = (s) => STATE_STYLE[s] || ['gray', (s || '?').toLowerCase()];

// Cap peer rows per service and outbound rows total — a wide scan can produce
// thousands; the header counts still show the true totals.
const SESS_PEERS_MAX = 40;
const SESS_OUT_MAX = 80;

function updateSessionHistory(observed, completeSnapshot) {
  const now = Date.now();
  const seen = new Set();
  for (const conn of observed) {
    const key = `${conn.proto}\t${conn.local}\t${conn.peer}`;
    seen.add(key);
    const old = sessionHistory.get(key);
    sessionHistory.set(key, {
      ...conn,
      proc: conn.proc || old?.proc || '',
      pid: conn.pid || old?.pid || '',
      firstSeen: old?.firstSeen || now,
      lastSeen: now,
      closedAt: null,
      active: true,
    });
  }

  for (const [key, conn] of sessionHistory) {
    if (conn.active && completeSnapshot && !seen.has(key)) {
      conn.active = false;
      conn.closedAt = now;
    } else if (!conn.active && now - conn.closedAt >= CLOSED_SESSION_TTL_MS) {
      sessionHistory.delete(key);
    }
  }

  if (sessionHistory.size > SESSION_HISTORY_MAX) {
    const removable = [...sessionHistory.entries()]
      .filter(([, conn]) => !conn.active)
      .sort((a, b) => a[1].closedAt - b[1].closedAt)
      .slice(0, sessionHistory.size - SESSION_HISTORY_MAX);
    for (const [key] of removable) sessionHistory.delete(key);
  }
  return [...sessionHistory.values()];
}

// Build and paint the sessions tree from one listening + one connection
// snapshot. Inbound conns (local port in the listen set) nest under their
// service; the rest are outbound, grouped by proc/peer/state with a count. `f`
// restricts the view to tunnel/HTB traffic. Wrapped so any failure shows an
// error line rather than silently leaving the panel blank.
async function renderSessions() {
  try {
    const [svc, connRes] = await Promise.all([collectListening(), collectConnections()]);
    const { conns: observed, truncated } = connRes;
    const conns = updateSessionHistory(observed, !truncated);
    const listenPorts = new Set([...svc.values()].map((e) => e.port));
    const outbound = [];
    for (const c of conns) {
      if (listenPorts.has(c.lport)) {
        const e = svc.get(`${c.proto}/${c.lport}`) || [...svc.values()].find((s) => s.port === c.lport);
        (e ? e.peers : outbound).push(c);
      } else {
        outbound.push(c);
      }
    }

    const tunnelOnly = filterTunnel && !!tunIP;
    const rel = (h) => h === tunIP || HTB_NET.test(h);
    const innerW = Math.max(28, (sessBox.width || 40) - 3);
    const lines = [];

    const services = [...svc.values()].sort((a, b) => {
      const aw = a.binds.has('0.0.0.0') || a.binds.has('*') || a.binds.has('::') ? 0 : 1;
      const bw = b.binds.has('0.0.0.0') || b.binds.has('*') || b.binds.has('::') ? 0 : 1;
      return aw - bw || (+a.port - +b.port);
    });

    let shownSvc = 0;
    const svcLines = [];
    for (const e of services) {
      const worldwide = e.binds.has('0.0.0.0') || e.binds.has('*') || e.binds.has('::');
      const rep = worldwide ? '0.0.0.0' : [...e.binds][0];
      const sc = bindScope(rep);
      const peers = tunnelOnly ? e.peers.filter((c) => rel(hostOf(c.peer))) : e.peers;
      if (tunnelOnly && !peers.length) continue;
      shownSvc++;
      const ucol = e.uid === 0 ? 'red' : 'cyan';
      const pidTag = e.pid ? `{gray-fg}[${e.pid}]{/}` : '';
      svcLines.push(`{${sc.fg}-fg}{bold}▾ :${e.port}{/} {white-fg}${e.proc}{/}${pidTag} `
        + `{${ucol}-fg}${userOf(e.uid)}{/} {${sc.fg}-fg}${sc.label}{/} {gray-fg}[${peers.length}]{/}`);
      for (const c of peers.slice(0, SESS_PEERS_MAX)) {
        if (!c.active) {
          const age = Math.max(0, Math.floor((Date.now() - c.closedAt) / 1000));
          svcLines.push(`    {red-fg}${fitCell(c.peer, innerW - 18)} closed ${age}s{/}`);
          continue;
        }
        const [scol, slabel] = stateStyle(c.state);
        svcLines.push(`    {${peerColor(hostOf(c.peer))}-fg}${fitCell(c.peer, innerW - 8)}{/} {${scol}-fg}${slabel}{/}`);
      }
      if (peers.length > SESS_PEERS_MAX) svcLines.push(`    {gray-fg}...+${peers.length - SESS_PEERS_MAX} more{/}`);
      if (!peers.length) svcLines.push(`    {gray-fg}. idle{/}`);
    }

    const og = new Map();
    for (const c of outbound) {
      if (tunnelOnly && !(rel(hostOf(c.peer)) || rel(hostOf(c.local)))) continue;
      const k = `${c.proto}\t${c.proc}\t${c.pid}\t${c.peer}\t${c.state}\t${c.active ? 1 : 0}`;
      const group = og.get(k);
      if (group) group.n++;
      else og.set(k, { n: 1, sample: c });
    }
    const outEntries = [...og.entries()].sort((a, b) => b[1].n - a[1].n || a[0].localeCompare(b[0]));
    const outLines = [];
    for (const [k, group] of outEntries.slice(0, SESS_OUT_MAX)) {
      const [proto, proc, pid, peer, state, active] = k.split('\t');
      const { n, sample } = group;
      if (active === '0') {
        const age = Math.max(0, Math.floor((Date.now() - sample.closedAt) / 1000));
        outLines.push(`  {red-fg}${proto} ${proc || '?'} -> ${fitCell(peer, innerW - 20)} closed ${age}s${n > 1 ? ` x${n}` : ''}{/}`);
        continue;
      }
      const [scol, slabel] = stateStyle(state);
      outLines.push(`  {gray-fg}${proto}{/} {cyan-fg}${proc || '?'}{/}${pid ? `{gray-fg}[${pid}]{/}` : ''} {gray-fg}->{/} `
        + `{${peerColor(hostOf(peer))}-fg}${fitCell(peer, innerW - 20)}{/} {${scol}-fg}${slabel}{/}`
        + `${n > 1 ? ` {gray-fg}x${n}{/}` : ''}`);
    }
    if (outEntries.length > SESS_OUT_MAX) outLines.push(`  {gray-fg}...+${outEntries.length - SESS_OUT_MAX} more{/}`);

    lines.push(`{bold}{underline}LISTENING{/} {gray-fg}${shownSvc}/${services.length}{/}`);
    lines.push(...(svcLines.length ? svcLines : ['  {gray-fg}(none){/}']));
    lines.push('');
    lines.push(`{bold}{underline}OUTBOUND{/} {gray-fg}${outEntries.length}{/}`);
    lines.push(...(outLines.length ? outLines : ['  {gray-fg}(none){/}']));
    if (truncated) lines.push(`{yellow-fg}~ heavy socket load — sampling first ${CONN_CAP} (scan?){/}`);

    const activeN = conns.filter((conn) => conn.active).length;
    sessBox.setLabel(` Sessions ${tunnelOnly ? '[tunnel]' : '[all]'} · ${activeN} active · ${conns.length - activeN} recent (f) `);
    sessBox.setContent(lines.join('\n'));
  } catch (err) {
    logRuntimeError('renderSessions', err);
    sessBox.setLabel(` Sessions · stale (${String((err && err.message) || err).split('\n')[0]}) `);
  }
}

// --- Live command exec via eBPF (bpftrace execsnoop) ---
// bpftrace is the one long-lived child. If it dies unexpectedly (OOM-killer,
// kernel probe teardown, transient sudo failure) the whole exec feed would go
// silent for the rest of the session, so we auto-restart it with a small,
// capped backoff. `quitting` suppresses the restart during a clean shutdown;
// the restart budget resets once a healthy stream of events resumes.
let quitting = false;
let traceRestarts = 0;
const MAX_TRACE_RESTARTS = 5;
const MAX_FLOW_CAPTURE_RESTARTS = 5;

function flowEndpoint(address, port) {
  if (!address) return '';
  if (!port) return address;
  return address.includes(':') ? `[${address}]:${port}` : `${address}:${port}`;
}

function captureInterfaceNames() {
  try {
    return fs.readdirSync('/sys/class/net')
      .filter((name) => readProc(`/sys/class/net/${name}/operstate`).trim() !== 'down')
      .sort();
  } catch {
    return Object.keys(os.networkInterfaces()).sort();
  }
}

function recordPacket(line) {
  const f = line.split('\t');
  if (f.length < 10) return;
  const timestamp = Math.round((Number(f[0]) || Date.now() / 1000) * 1000);
  const ifaceName = f[1] || '?';
  const srcAddress = f[2], dstAddress = f[5];
  const srcPort = f[3] || f[4], dstPort = f[6] || f[7];
  if (!srcAddress || !dstAddress) return;
  const protocol = f[3] || f[6] ? 'tcp'
    : f[4] || f[7] ? 'udp'
      : (f[8] || '?').toLowerCase();
  const src = flowEndpoint(srcAddress, srcPort);
  const dst = flowEndpoint(dstAddress, dstPort);
  const key = `${ifaceName}\t${protocol}\t${src}\t${dst}`;
  const old = flows.get(key);
  flows.set(key, {
    iface: ifaceName,
    protocol,
    src,
    dst,
    packets: (old?.packets || 0) + 1,
    bytes: (old?.bytes || 0) + (Number(f[9]) || 0),
    firstSeen: old?.firstSeen || timestamp,
    lastSeen: timestamp,
  });

  // Avoid sorting the whole flow map for every packet once it is full. On a
  // busy host that can starve Blessed's redraw/input loop and look like a hang.
  if (flows.size > FLOW_MAX + 256) flowEvictionPending = true;
  if (flowEvictionPending) {
    const oldest = [...flows.entries()]
      .sort((a, b) => a[1].lastSeen - b[1].lastSeen)
      .slice(0, flows.size - FLOW_MAX);
    for (const [keyToDrop] of oldest) flows.delete(keyToDrop);
    flowEvictionPending = false;
  }
}

function renderFlows() {
  const now = Date.now();
  for (const [key, flow] of flows) {
    if (now - flow.lastSeen >= FLOW_TTL_MS) flows.delete(key);
  }
  const innerW = Math.max(28, (flowBox.width || 40) - 3);
  const endpointW = Math.max(8, Math.floor((innerW - 25) / 2));
  const visibleFlows = [...flows.values()]
    .filter((flow) => !filterTunnel || /^(tun|tap)\d+$/.test(flow.iface));
  const lines = visibleFlows
    .sort((a, b) => b.lastSeen - a.lastSeen || b.packets - a.packets)
    .slice(0, 200)
    .map((flow) => {
      const age = Math.max(0, Math.floor((now - flow.lastSeen) / 1000));
      return `{yellow-fg}${fitCell(flow.iface, 8).padEnd(8)}{/} `
        + `{cyan-fg}${fitCell(flow.protocol, 5).padEnd(5)}{/} `
        + `${fitCell(flow.src, endpointW)} {gray-fg}->{/} ${fitCell(flow.dst, endpointW)} `
        + `{green-fg}x${flow.packets}{/} {gray-fg}${age}s{/}`;
    });
  flowBox.setLabel(` Packet Flows ${visibleFlows.length} ${filterTunnel ? '[tunnel]' : '[all]'} · 60s idle · ${flowCaptureStatus} `);
  flowBox.setContent(lines.length
    ? lines.join('\n')
    : `{gray-fg}(${filterTunnel ? 'waiting for tunnel packets' : 'waiting for packets'}){/}`);
}

function startFlowCapture(interfaceNames = captureInterfaceNames()) {
  flowCaptureStatus = 'starting';
  const args = [
    '-n', 'tshark', '-l', '-n', '-Q',
    ...interfaceNames.flatMap((name) => ['-i', name]),
    '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=f',
    '-e', 'frame.time_epoch',
    '-e', 'frame.interface_name',
    '-e', '_ws.col.Source',
    '-e', 'tcp.srcport',
    '-e', 'udp.srcport',
    '-e', '_ws.col.Destination',
    '-e', 'tcp.dstport',
    '-e', 'udp.dstport',
    '-e', '_ws.col.Protocol',
    '-e', 'frame.len',
  ];
  flowCaptureSignature = interfaceNames.join('\t');
  const child = monitoredSpawn('sudo', args);
  let buf = '';
  child.stdout.on('data', (data) => {
    try {
      flowCaptureStatus = 'live';
      if (flowCaptureRestarts) flowCaptureRestarts = 0;
      buf += data.toString();
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) if (line) recordPacket(line);
    } catch (err) {
      logRuntimeError('tshark stdout handler', err);
    }
  });
  child.stderr.on('data', (data) => {
    const message = data.toString().trim();
    if (/password|not permitted|permission denied|capabilit|error/i.test(message)) {
      flowCaptureStatus = 'capture error';
      logRuntimeError('tshark stderr', new Error(message));
    }
  });
  child.on('error', (err) => {
    flowCaptureStatus = 'spawn error';
    logRuntimeError('tshark spawn', err);
  });
  child.on('exit', (code) => {
    if (quitting) return;
    if (flowCaptureReconfigure) {
      flowCaptureReconfigure = false;
      flowTrace = startFlowCapture();
      return;
    }
    flowCaptureStatus = `offline (${code ?? '?'})`;
    if (flowCaptureRestarts < MAX_FLOW_CAPTURE_RESTARTS) {
      flowCaptureRestarts++;
      flowCaptureStatus = `restarting ${flowCaptureRestarts}/${MAX_FLOW_CAPTURE_RESTARTS}`;
      setTimeout(() => {
        if (!quitting) flowTrace = startFlowCapture();
      }, 2000);
    }
  });
  return child;
}

function ensureFlowCaptureInterfaces() {
  const signature = captureInterfaceNames().join('\t');
  if (!flowTrace || signature === flowCaptureSignature || flowCaptureReconfigure) return;
  flowCaptureReconfigure = true;
  flowCaptureStatus = 'reconfiguring';
  monitoredExecFile('sudo', ['-n', 'kill', '-TERM', String(flowTrace.pid)], { timeout: 3000 }, (err) => {
    if (err) {
      flowCaptureReconfigure = false;
      logRuntimeError('tshark interface reconfigure', err);
    }
  });
}

// bpftrace runs under sudo (root), so this node process (the user) cannot signal
// it. On an unclean exit (terminal closed, SIGTERM/SIGKILL) our quit() never
// runs, the tracer is orphaned, and it keeps running. A freshly-launched monitor
// then coexists with the orphan(s) and EVERY exec is reported once per live
// tracer — the "duplicate commands" symptom, multiplying with each unclean
// restart. pkill runs as root via sudo so it can actually reap them; scoped by
// pattern to ONLY our trace script. Run on startup (clear orphans before we
// spawn ours) and on quit (reap the root child we can't kill directly).
const TRACE_MATCH = 'bpftrace.*exec-trace\\.bt';
const FLOW_MATCH = 'tshark.*frame\\.interface_name.*_ws\\.col\\.Source';
function killStaleTracersSync() {
  try { execFileSync('sudo', ['-n', 'pkill', '-f', TRACE_MATCH], { timeout: 3000, stdio: 'ignore' }); } catch {}
}
function killStaleFlowCapturesSync() {
  try { execFileSync('sudo', ['-n', 'pkill', '-f', FLOW_MATCH], { timeout: 3000, stdio: 'ignore' }); } catch {}
}

// Defense-in-depth against duplicates during the brief auto-restart overlap
// window: suppress an identical pid+comm+argv seen within DEDUP_MS. A genuine
// re-exec always carries a new pid, so this can only ever drop a true echo, not
// a real event. Bounded by a periodic sweep + a hard size guard.
const DEDUP_MS = 1500;
const recentExec = new Map();   // "pid\tcomm\targv" -> ts(ms)
function isDupExec(pid, comm, argv, tsMs) {
  if (recentExec.size > 20000) sweepRecentExec();
  const k = `${pid}\t${comm}\t${argv}`;
  const prev = recentExec.get(k);
  recentExec.set(k, tsMs);
  return prev !== undefined && tsMs - prev < DEDUP_MS;
}
function sweepRecentExec() {
  const now = Date.now();
  for (const [k, ts] of recentExec) if (now - ts > DEDUP_MS) recentExec.delete(k);
}

function startExecTrace() {
  const bt = monitoredSpawn('sudo', ['-n', 'bpftrace', path.join(__dirname, 'exec-trace.bt')]);
  let buf = '';
  bt.stdout.on('data', (d) => {
    try {
      if (traceRestarts) traceRestarts = 0;   // healthy output → reset backoff budget
      buf += d.toString();
      const lines = buf.split('\n'); buf = lines.pop();
      for (const ln of lines) {
        if (!ln.startsWith('E\t')) continue;
        const [, uid, pid, ppid, comm, ...rest] = ln.split('\t');
        const argv = rest.join(' ');
        const origin = classifyExecOrigin(+pid, +ppid, comm);
        // Always log everything to disk. The live-view filters are applied
        // only after the audit entry has been queued.
        const now = new Date();
        // Drop echoes of the same exec from an overlapping tracer before they
        // reach disk / the tally / the pane (see isDupExec).
        if (isDupExec(pid, comm, argv, now.getTime())) continue;
        const line = `${now.toISOString()}\t${origin}\t${uid}\t${pid}\t${comm}\t${argv}\n`;
        logBuf.push(line); logBufBytes += line.length;
        if (logBufBytes > 256 * 1024) flushLogBuf(); // hard flush at 256 KB backlog
        // Keep a complete disk audit, but do not let the panel's recurring
        // plugin/launcher subprocesses pollute the live view or its counters.
        if (origin === 'mine' || origin === 'xfce-panel') continue;
        // tally by category into the rolling 1h window + light up its icon
        // (independent of the on-screen view filter)
        const cat = categorize(comm, argv);
        const ts = now.getTime();
        rollBuckets(ts);
        catBuckets[cat][bucketMin % BUCKET_MIN]++;
        catLastTs[cat] = ts;
        cmdTotal++;
        // feed the status banner regardless of the on-screen command filter
        if (origin === 'hexstrike') { lastHexTs = now.getTime(); lastCmdText = escapeBlessed(`${comm} ${argv}`.trim()); }
        else if (origin === 'ssh') { lastActTs = now.getTime(); lastCmdText = escapeBlessed(`${comm} ${argv}`.trim()); }
        if (hexOnly && origin !== 'hexstrike') continue;
        const tag = origin === 'hexstrike' ? '{magenta-fg}hexstrike{/}'
          : origin === 'ssh' ? '{green-fg}ssh{/}' : '{gray-fg}local{/}';
        const who = uid === '0' ? '{red-fg}root{/}' : `uid${uid}`;
        cmdLog.log(`{gray-fg}${now.toLocaleTimeString()}{/} ${tag} ${who} {cyan-fg}${escapeBlessed(comm)}{/}[${pid}] ${escapeBlessed(argv)}`);
      }
    } catch (err) {
      logRuntimeError('bpftrace stdout handler', err);
    }
  });
  bt.stderr.on('data', (d) => {
    const s = d.toString();
    if (/password|not permitted|ERROR/i.test(s)) {
      cmdLog.log(`{red-fg}bpftrace: ${escapeBlessed(s.trim())}{/}`);
      logRuntimeError('bpftrace stderr', new Error(s.trim()));
    }
  });
  bt.on('error', (err) => {
    logRuntimeError('bpftrace spawn', err);
  });
  bt.on('exit', (code) => {
    if (quitting) return;
    cmdLog.log(`{red-fg}bpftrace exited (${code}) — exec trace stopped{/}`);
    if (traceRestarts < MAX_TRACE_RESTARTS) {
      traceRestarts++;
      cmdLog.log(`{yellow-fg}[trace] restarting bpftrace (attempt ${traceRestarts}/${MAX_TRACE_RESTARTS})…{/}`);
      setTimeout(() => { if (!quitting) trace = startExecTrace(); }, 2000);
    } else {
      cmdLog.log(`{red-fg}[trace] gave up after ${MAX_TRACE_RESTARTS} restarts — exec feed offline{/}`);
    }
    screen.render();
  });
  return bt;
}

// ---------------------------------------------------------------- lifecycle
// Redraw the animated status banner (fast, cheap — no /proc reads).
function renderArt() {
  frame++;
  const state = deriveState({ now: Date.now(), vpnUp: !!iface, lastHexTs, lastActTs, bwIntensity });
  const intensity = state === 'attack' ? 1
    : state === 'active' ? Math.max(0.55, bwIntensity)
      : state === 'idle' ? 0.18 : 0.12;
  const detail = (state === 'attack' || state === 'active') ? lastCmdText : '';
  artBox.style.border.fg = state === 'attack' ? 'red' : state === 'active' ? 'yellow' : state === 'idle' ? 'green' : 'red';
  artBox.setContent(buildArt(artBox.width - 2, {
    state, frame, vpn: { up: !!iface, ip: tunIP }, detail, intensity, height: artBox.height - 2,
    hex: { serverUp: hexServerUp, tools: hexTools, mcp: hexMcpCount > 0 },
  }));
  screen.render();
}

const SESS_MS = 1000;                    // fast active-session lifecycle refresh
killStaleTracersSync();                  // reap orphan tracers from a prior run
killStaleFlowCapturesSync();             // reap an orphan monitor-owned tshark
let trace = startExecTrace();            // reassigned by the auto-restart path
let flowTrace = startFlowCapture();       // packet metadata from every up iface
const timer = guardedAsyncInterval('tick', tick, 1000);
const artTimer = guardedInterval('renderArt', renderArt, 220);
const ancSweepTimer = guardedInterval('cacheSweep', () => {
  sweepAncCache(); sweepMonitorPids(); sweepRecentExec();
}, 30_000);
const hexTimer = guardedAsyncInterval('hexHealthTick', hexHealthTick, HEX_MS);        // hexstrike /health
const sessTimer = guardedAsyncInterval('refreshSessions', refreshSessions, SESS_MS);  // slow sessions poll
timer.run();
artTimer.run();
hexTimer.run();
sessTimer.run();

// Reflow on terminal resize: the contrib grid is proportional, so just
// re-feed data (re-renders every canvas at the new size) and repaint.
screen.on('resize', () => {
  layoutDashboard();
  timer.run();
  artTimer.run();
  sessTimer.run();
});

// Command pane gets keyboard focus so ↑↓/j/k/PgUp/PgDn/g/G scroll it; the
// mouse wheel works on hover regardless. End jumps back to live tail.
cmdLog.focus();
cmdLog.key(['end'], () => { cmdLog.setScrollPerc(100); cmdLog._userScrolled = false; screen.render(); });
// Tab cycles keyboard focus through every scrollable live pane.
const focusables = [cmdLog, vpnBox, cpuBox, sessBox, flowBox];
screen.key(['tab'], () => {
  const idx = focusables.indexOf(screen.focused);
  focusables[(idx + 1) % focusables.length].focus();
  screen.render();
});

screen.key(['f'], () => {
  filterTunnel = !filterTunnel;
  renderFlows();
  sessTimer.run();
  screen.render();
});
screen.key(['a'], () => {
  hexOnly = !hexOnly;
  cmdLog.setLabel(hexOnly
    ? ' Commands [hexstrike]  ↑↓/wheel scroll · End=live · a=all '
    : ' Commands [all]  ↑↓/wheel scroll · End=live · a=hexstrike ');
  screen.render();
});

let quitStarted = false;
function quit({ restart = false } = {}) {
  if (quitStarted) return;         // 'C-c' key + SIGINT both fire — run once only,
  quitStarted = true;              // a second screen.destroy() spews stray escapes
  quitting = true;                 // suppress the bpftrace auto-restart
  clearTimeout(selfRefreshTimer);
  clearInterval(timer);
  clearInterval(artTimer);
  clearInterval(wdTimer);
  clearInterval(ancSweepTimer);
  clearInterval(hexTimer);
  clearInterval(sessTimer);
  clearInterval(logFlushTimer); flushLogBuf();
  try { execLogStream.end(); } catch {}
  try {
    if (trace.pid) process.kill(trace.pid, 0) && trace.kill('SIGTERM');
  } catch (err) {
    if (err?.code !== 'EPERM') logRuntimeError('trace shutdown', err);
  }
  try {
    if (flowTrace.pid) monitoredExecFile('sudo', ['-n', 'kill', '-TERM', String(flowTrace.pid)], { timeout: 3000 }, () => {});
  } catch (err) {
    logRuntimeError('tshark shutdown', err);
  }
  // Restore the terminal FIRST so the console is clean the instant you hit q —
  // reaping the root tracer used to block here (synchronous `sudo pkill`, up to
  // a 3s timeout) with the alt-screen still up, which is what made quit feel
  // slow and left half-written escape sequences on screen. Now: tear down the
  // UI, then reap in the background and exit from its callback so blessed's
  // terminal-reset output flushes fully before the process dies.
  try { screen.destroy(); } catch (err) {
    // The terminal may already have disappeared (SSH disconnect/PTY EIO).
    // Cleanup below is still useful, but a second terminal reset cannot work.
    if (err?.code !== 'EIO') logRuntimeError('screen shutdown', err, { ui: false });
  }
  const done = () => {
    if (restart) {
      const child = monitoredSpawn(process.execPath, process.argv.slice(1), {
        cwd: process.cwd(), env: process.env, stdio: 'inherit',
      });
      child.unref();
    }
    process.exit(0);
  };
  try {
    let cleanupPending = 2;
    const cleaned = () => { if (--cleanupPending === 0) done(); };
    monitoredExecFile('sudo', ['-n', 'pkill', '-f', TRACE_MATCH], { timeout: 3000 }, cleaned);
    monitoredExecFile('sudo', ['-n', 'pkill', '-f', FLOW_MATCH], { timeout: 3000 }, cleaned);
    setTimeout(done, 3500).unref();   // safety net if the callback never fires
  } catch { done(); }
}

const selfRefreshTimer = setTimeout(() => {
  try {
    cmdLog.log('{yellow-fg}[monitor] refreshing kali-mon after one hour{/}');
    screen.render();
  } catch {}
  quit({ restart: true });
}, SELF_REFRESH_MS);
selfRefreshTimer.unref();

screen.key(['q', 'escape', 'C-c'], quit);
// Cover every way the monitor can be told to stop, so the root tracer is always
// reaped (an unhandled SIGTERM/SIGHUP would orphan it → duplicate commands).
process.on('SIGINT', quit);
process.on('SIGTERM', quit);
process.on('SIGHUP', quit);
process.on('unhandledRejection', (err) => {
  logRuntimeError('unhandledRejection', err);
});
process.on('uncaughtException', (err) => {
  logRuntimeError('uncaughtException', err);
});
