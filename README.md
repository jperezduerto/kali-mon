# kali-mon

`kali-mon` is a public, self-contained terminal dashboard for monitoring a
Linux/Kali workstation. It reports VPN/LAN state, CPU and memory, routes,
sockets, packet flows, and system-wide command activity without sending data
to a remote service.

The project is intentionally machine-agnostic: it reads the local kernel and
network state at runtime and does not contain hostnames, addresses, credentials,
logs, or private configuration.

## Quick start

```bash
git clone https://github.com/jperezduerto/kali-mon.git
cd kali-mon
npm ci
./htb-monitor
```

Run it in a real terminal, SSH session with a PTY (`ssh -t`), or tmux. It needs
Node.js 18+, `iproute2`, `tshark`, `bpftrace`, and passwordless sudo for the
privileged socket and capture views. The dashboard remains useful without the
optional capture tools, but those panels will be unavailable.

## Updating an existing checkout

From the repository directory:

```bash
./update.sh
```

The updater refuses to overwrite local modifications, fast-forwards from
GitHub, and installs the exact locked dependencies with `npm ci`. To inspect
changes before updating, use `git pull --ff-only --dry-run` (or `git fetch` and
`git diff HEAD..origin/main`).

## Privacy

Runtime data is displayed locally and logs are excluded by `.gitignore`.
Before sharing a fork or patch, keep `logs/` out of commits and review any
local changes with `git diff`.

## Development

```bash
npm ci
npm test
```

The GitHub Actions workflow runs the same syntax checks on every push and pull
request.

---

# htb-monitor

Single-console live visibility for the local Kali box. A `blessed-contrib`
terminal dashboard that **auto-fits the terminal** (proportional 12×12 grid,
reflows on resize) with a dynamic ASCII status banner plus focused live panels:

| Panel | Source |
|-------|--------|
| **Status banner** — animated ASCII art (see below) | derived state |
| Per-core CPU usage (htop-style bars) + 5-min peak tick + load | `/proc/stat`, `os.loadavg()` |
| VPN/LAN status, live bandwidth/RAM, and IPv4 routing destinations | `ip addr`, `ip route`, `/proc` |
| Active + recently closed TCP/UDP sessions (tunnel-filterable) | `sudo ss -tunp` |
| Real-time directional packet flows on every active interface | `sudo tshark` |
| Live command execution (hexstrike + SSH shells, **scrollable**) | eBPF via `sudo bpftrace exec-trace.bt` |
| Command activity — per-category icons + rolling 1h counts | classified from the exec stream |
| Top processes by memory (RSS) and by CPU (%CPU) | `ps -eo rss=,pcpu=,comm=` |
| Bottom status bar (user@host · clock · keys · active filters) | `os` + live state |

Layout: top-left column splits into the status banner over the per-core CPU
box; command-category stats fill the top-middle, with side-by-side **Top Mem**
and **Top CPU** process tiles beneath them. A scrollable **VPN & Routes** panel
fills the top-right, with tunnel destinations prioritized and highlighted.
The bottom half keeps Sessions and Packet Flows together in a
horizontal split beside a wide, scrollable command pane. It resizes with the
window — no fixed dimensions.

The two process tiles share one `ps` snapshot per tick. **Top CPU** uses ps's
lifetime-average per-process `%CPU` (can exceed 100% on multicore), consistent
with the hexstrike watchdog — it flags sustained hogs, not sub-second spikes.

**Per-core CPU** draws the live utilization bar plus a red `┃` tick marking each
core's highest reading over the trailing 5 minutes (300 one-second samples), so
a spike stays visible after the core goes idle. The box label shows the current
average and the max peak across all cores (`peak5m`).

**Command activity** shows one row per tool category (recon 📡, web 🌐, creds 🔑,
ad 🏰, exploit 💥, shell 🐚, other 📦) in a fixed order. The emoji require the
screen's `fullUnicode: true` (set in `index.js`) plus a terminal with a
color-emoji fallback font (e.g. NotoColorEmoji) — without fullUnicode blessed
renders astral-plane codepoints as `?`. A category's icon lights up (colored
chip) for a few seconds each time a matching command is detected, and
the number beside it is that category's command count over the **last hour**
(kept as 60 one-minute buckets, so it's a true rolling window at constant memory).
The `Σ 1h` footer totals the window; `session` is the lifetime count.

### Status banner (`art.js`)

A self-animating ASCII panel (no external deps) that reflects live state at
~5 fps:

| State | When | Look |
|-------|------|------|
| `OFFLINE` | no tun interface | red, slow `×` marquee, `○ NO TUNNEL` |
| `IDLE` | VPN up, no recent activity | cyan, calm wave |
| `ACTIVE` | recent SSH command or bandwidth flowing | yellow, faster wave + last command |
| `ATTACK` | a hexstrike tool ran in the last 4 s | red blinking `! ATTACK !`, fast `▸▸×` marquee + last command |

The wave amplitude tracks live tunnel throughput; the border colour and
marquee speed track the state.

## Run

```bash
node index.js      # or ./htb-monitor   or   npm start
```

### Keys

- `q` / `Esc` / `Ctrl-C` — quit
- `↑`/`↓`, `j`/`k`, `PgUp`/`PgDn`, `g`/`G`, **mouse wheel** — scroll the command pane
  (auto-follow pauses while scrolled up; resumes at the bottom). `End` jumps to live.
- `Tab` — move keyboard focus between Commands, VPN & Routes, Sessions, and Packet Flows
- `f` — toggle the session and packet-flow panes between **all** traffic
  (default) and **tunnel-only**
- `a` — toggle the command pane between **all execs** (default) and **hexstrike-only**

### Command-category stats

Every non-self command is bucketed into one of seven categories and tallied
live (sorted bar chart, with a running total):

| Category | Matches (examples) |
|----------|--------------------|
| `recon` | nmap, masscan, rustscan, subfinder, amass, dnsenum, whois, ping |
| `web` | gobuster, ffuf, feroxbuster, nikto, nuclei, sqlmap, wpscan, curl/wget |
| `creds` | hydra, john, hashcat, medusa, crack* |
| `ad` | impacket, nxc/netexec, smbclient/smbmap, ldapsearch, bloodhound, kerbrute, evil-winrm |
| `exploit` | msfconsole, msfvenom, searchsploit, gdb, radare2, pwntools, sliver |
| `shell` | bash/sh/zsh, nc/socat, python, ssh/scp, whoami/id/uname, coreutils |
| `other` | anything unmatched |

Categories are matched in that priority order (cracking before AD, AD before
web) so overlapping tools land in the most specific bucket.

## Extras

- **VPN & Routes** — the top-right panel combines tunnel/LAN addresses, RAM,
  live tunnel KB/s and packet rates, and every destination in the IPv4 main
  routing table. Tunnel routes are highlighted and shown first; scroll the
  panel for the remaining connected, default, link-down, and special routes.
- **Traffic filter** — the session table and packet-flow pane show **all**
  traffic by default. Press `f` to restrict sessions to tunnel traffic (local
  == your tun IP, or peer in the `10.10.0.0/15` / `10.129.0.0/16` HTB ranges)
  and packet flows to `tunX`/`tapX` interfaces.
- **Stable session lifecycle** — sockets refresh every second. A disappeared
  session remains visible in red with a `closed Ns` age and is removed after
  60 seconds. Failed or truncated `ss` snapshots do not falsely close rows.
- **Packet flows** — packet metadata is aggregated directionally by interface,
  protocol, source address/port, and destination address/port. The always-live
  panel catches UDP, ICMP, ARP, and short TCP communication that may never
  appear as a settled socket. Idle flows expire after 60 seconds.
- **Command origin filter** — every `execve()` is classified by walking its
  parent chain in `/proc`. By default the pane shows **all** origins; press `a`
  to filter down to **hexstrike-only**:
  - `hexstrike` — descends from the HexStrike server/agent (the pentest tools
    it runs). Tagged magenta. The only origin kept when the `a` filter is on.
  - `ssh` — descends from an `sshd` session (interactive remote shells).
    Tagged green.
  - `xfce-panel` — descends from `xfce4-panel`. Always hidden from the pane and
    activity counters to suppress recurring desktop plugin/launcher noise.
  - `mine` — inside this dashboard's own process tree (its `ss`/`bpftrace`/`ip`
    polls). **Always hidden** from the pane so it never shows its own noise.
  - `other` — local desktop shells, daemons, cron. Tagged gray.

  Caveat: classification reads `/proc` just after the exec, so a very
  short-lived parent that exits and has its PID recycled before the read can
  be mistagged. The parents that matter (hexstrike server, your SSH shell) are
  long-lived and classify reliably.

- **Exec history log** — *every* captured `execve()` (including
  `mine`/`xfce-panel`/`other`) is appended to `logs/exec-history.log` as TSV
  (`ISO-ts  origin  uid  pid  comm  argv`) for a full audit trail regardless of
  the on-screen filter. e.g. `grep -P '\thexstrike\t' logs/exec-history.log`.

## How it works

The TUI runs as your normal user. Only the three privileged data sources are
spawned via `sudo -n`:

- **`ss -tunp`** — needs root to see process names for every socket.
- **`tshark` on each active interface** — streams packet metadata only; packet
  payloads are neither displayed nor retained. Capture restarts automatically
  when the interface set changes.
- **`bpftrace exec-trace.bt`** — attaches to the `sys_enter_execve`
  tracepoint and streams *every* `execve()` system-wide, so you see commands
  from every shell, cron job, and subprocess — not just your interactive zsh.

Both rely on the passwordless `sudo` already configured on this box. If you
run on a machine without it, launch the whole thing with `sudo node index.js`.

## Long-running behaviour (resource model)

Designed to stay up for days without leaking. Everything whose size could grow
with time or traffic is explicitly bounded:

| State | Bound |
|-------|-------|
| Command pane (`cmdLog`) | `scrollback: 2000` lines |
| Exec log on disk | rotated at 50 MB × 3 files; writes batched every 2 s |
| Ancestor cache (`ancCache`) | expired entries (>8 s) swept every 30 s; hard cap of 4096 |
| Watchdog spin tracker (`spinWatch`) | stale PIDs pruned each 15 s pass |
| `username` / `hostname` | resolved once at startup, not per tick |
| `/proc/net/dev` | read once per tick, shared by interface detection + counters |
| Session history (`sessionHistory`) | closed rows expire after 60 s; hard cap of 12,000 |
| Packet flows (`flows`) | 60 s idle expiry; hard cap of 4,096 |

The long-lived capture children are **bpftrace** and **tshark**. Both
auto-restart with capped backoff if their feed exits, and stale monitor-owned
capture processes are reaped on startup and shutdown.

## Requirements

- `node` (tested on v24)
- `bpftrace` (`apt install bpftrace` — also baked into `~/kaliconfig/justdoit.sh`)
- `iproute2` (`ss`, `ip` — stock on Kali)
- `tshark` (`apt install tshark` — also baked into `~/kaliconfig/justdoit.sh`)

## Config

- `HTB_IFACE=tun1 node index.js` — force a specific tunnel interface.
  By default it auto-detects the first `tun*`/`tap*` in `/proc/net/dev`,
  so it follows your HTB VPN whether it comes up as `tun0` or `tun1`.
