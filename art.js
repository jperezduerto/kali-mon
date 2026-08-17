// Dynamic ASCII status art for the dashboard.
// buildArt(width, ctx) returns a centered, width-aware, blessed-tagged string.
// Everything here uses width-1 BMP glyphs only (no emoji) so centering math
// stays correct across terminals and the panel never wraps unexpectedly.

const BLOCKS = ' ▁▂▃▄▅▆▇█';

// A flowing sine wave whose amplitude tracks `intensity` (0..1).
function wave(width, frame, intensity) {
  let s = '';
  for (let i = 0; i < width; i++) {
    const v = (Math.sin(i * 0.4 + frame * 0.5) + 1) / 2;       // 0..1
    const lvl = Math.round(v * intensity * (BLOCKS.length - 1));
    s += BLOCKS[Math.min(BLOCKS.length - 1, Math.max(0, lvl))];
  }
  return s;
}

// A scrolling marquee built from a tiled pattern.
function marquee(width, frame, pattern, speed = 1) {
  const off = (Math.floor(frame * speed)) % pattern.length;
  const tiled = pattern.repeat(Math.ceil((width + pattern.length) / pattern.length));
  return tiled.slice(off, off + width);
}

const SCENES = {
  offline: { c: 'red',     word: 'VPN OFFLINE', pat: '×    ', speed: 0.4 },
  idle:    { c: 'cyan',    word: 'TUNNEL UP',   pat: '·    ', speed: 0.5 },
  active:  { c: 'yellow',  word: 'ACTIVE',      pat: '▸    ', speed: 1.2 },
  attack:  { c: 'red',     word: '! ATTACK !',  pat: '▸▸×  ', speed: 2.2 },
};

const strip = (s) => s.replace(/\{[^}]*\}/g, '');

export function buildArt(width, { state, frame, vpn, detail, intensity, height, hex }) {
  const W = Math.max(12, width || 30);
  const sc = SCENES[state] || SCENES.idle;
  const cap = Math.min(W, 46);
  const center = (s) => ' '.repeat(Math.max(0, Math.floor((W - strip(s).length) / 2))) + s;

  const blink = state === 'attack' && frame % 2 === 0;
  const wordColor = blink ? 'white' : sc.c;
  const spacedWord = sc.word.split('').join(' ');

  // Compact core (no padding) so it fits a short box; we vertically center
  // it afterwards based on the available height.
  const core = [
    center(`{${sc.c}-fg}${marquee(cap, frame, sc.pat, sc.speed)}{/}`),
    center(`{${wordColor}-fg}{bold}${spacedWord}{/}`),
    center(`{${sc.c}-fg}${wave(cap, frame, intensity)}{/}`),
    center(`{${sc.c}-fg}${wave(cap, frame + 4, intensity * 0.75)}{/}`),
  ];
  if (detail) core.push(center(`{gray-fg}${strip(detail).slice(0, W - 2)}{/}`));
  core.push(center(vpn.up
    ? `{green-fg}{bold}● TUNNEL{/}{green-fg} ${vpn.ip || 'up'}{/}`
    : `{red-fg}{bold}○ NO TUNNEL{/}`));
  // HexStrike MCP service line (BMP ●/○ only — see file header re: no emoji).
  if (hex) core.push(center(hex.serverUp
    ? `{green-fg}{bold}● HEXSTRIKE{/}{green-fg} ${hex.tools} tools{/}`
      + (hex.mcp ? '' : ' {yellow-fg}·no mcp{/}')
    : `{red-fg}{bold}○ HEXSTRIKE down{/}`));

  // Vertically center within the box, inserting a blank between rows when
  // there's spare height so a tall box doesn't look cramped at the top.
  const H = height || core.length;
  let body = core;
  if (H >= core.length * 2) body = core.flatMap((l) => [l, '']).slice(0, -1);
  const pad = Math.max(0, Math.floor((H - body.length) / 2));
  return Array(pad).fill('').concat(body).join('\n');
}

// Decide the scene from recent activity timestamps + live intensity.
export function deriveState({ now, vpnUp, lastHexTs, lastActTs, bwIntensity }) {
  if (now - lastHexTs < 4000) return 'attack';
  if (now - lastActTs < 3000 || bwIntensity > 0.06) return 'active';
  return vpnUp ? 'idle' : 'offline';
}
