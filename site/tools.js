// Single source of truth for the static showcase. Both the landing grid
// (index.html) and the per-tool pages (tool.html) render from this.

const REPO_URL = 'https://github.com/denvercoder/rusty-tools.git';

const GROUPS = ['Network', 'Host detection / audit', 'Malware analysis'];

const TOOLS = [
  {
    id: 'portofino', icon: '🔍', name: 'Portofino', group: 'Network',
    blurb: 'Multithreaded TCP port scanner — a single host, a range, or a CIDR block, with live progress and an open-ports summary that stays readable across hundreds of hosts.',
    cli: ['# Interactive wizard', 'cargo run -p Portofino', '', '# Non-interactive / scriptable', 'cargo run -p Portofino -- --threads 500 --target 10.0.0.0/24 --ports common'],
    prefixes: [['PORT n is Open', 'An open port found on a scanned host']],
  },
  {
    id: 'pppp', icon: '📡', name: 'PPPP (4P)', group: 'Network',
    blurb: 'PickAPeckOfPacketParsers — live packet capture & parsing (Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP), with DNS/HTTP decoding and live port-scan / ARP-spoof alerts. Linux; needs CAP_NET_RAW.',
    cli: ['# List interfaces', 'cargo run -p PickAPeckOfPacketParsers -- --list', '', '# Capture (after: sudo setcap cap_net_raw+ep the binary)', './target/release/PickAPeckOfPacketParsers wlan0 --protocol tcp --port 443'],
    prefixes: [['TCP / UDP / ICMP / ARP', 'Per-protocol summary line'], ['DNS', 'Decoded query/response + record type'], ['HTTP', 'Plaintext request/status + Host'], ['ALERT', 'Live port-scan or ARP-spoof detection']],
  },
  {
    id: 'oneforthehoney', icon: '🍯', name: 'OneForTheHoney', group: 'Network',
    blurb: 'Decoy-service honeypot — binds the ports scanners and bots probe most, logs every connection attempt with fake banners, and flags a source that sweeps several decoy ports. Linux; low ports need CAP_NET_BIND_SERVICE.',
    cli: ['./target/release/OneForTheHoney --ports 22,80,3389', './target/release/OneForTheHoney --bind 127.0.0.1'],
    prefixes: [['CONN', 'A connection hit a decoy port'], ['DATA', 'Bytes the client sent'], ['ALERT', 'One source touched 3+ decoy ports quickly']],
  },
  {
    id: 'bunyan', icon: '🪵', name: 'Bunyan', group: 'Host detection / audit',
    blurb: 'systemd-journal auth log analyzer — sshd & sudo activity only, with live brute-force and compromised-credential alerts. Linux.',
    cli: ['# Live', './target/release/Bunyan', '', '# Replay a saved export', './target/release/Bunyan --file sample.jsonl'],
    prefixes: [['LOGIN', 'An sshd login attempt (ok / fail)'], ['SUDO', 'A sudo command or auth failure'], ['ALERT', 'Brute force or a possible compromise']],
  },
  {
    id: 'feefifofim', icon: '👣', name: 'FeeFiFoFIM', group: 'Host detection / audit',
    blurb: 'File integrity monitor — a SHA-256 baseline of a directory, then reports anything added, removed, or changed. Classic host-based integrity monitoring.',
    cli: ['# Baseline', './target/release/FeeFiFoFIM /etc --init', '', '# Check (optionally --watch 30)', './target/release/FeeFiFoFIM /etc'],
    prefixes: [['ADDED', 'A file that was not in the baseline'], ['REMOVED', 'A baseline file that is now gone'], ['MODIFIED', "A file's content hash changed"]],
  },
  {
    id: 'hardhat', icon: '⛑️', name: 'HardHat', group: 'Host detection / audit',
    blurb: 'Security config auditor — a one-shot posture check of SSH config, accounts, sudoers, firewall status, SUID binaries, and sensitive file permissions. Linux; more checks unlock with sudo.',
    cli: ['./target/release/HardHat', 'sudo ./target/release/HardHat   # also runs sudoers/shadow checks'],
    prefixes: [['PASS', 'Nothing concerning'], ['WARN', 'Worth a look'], ['FAIL', 'A clear hardening gap'], ['SKIP', 'Needs root and did not have it']],
  },
  {
    id: 'fafo', icon: '🐤', name: 'FuckAroundFindOut', group: 'Malware analysis',
    blurb: 'Network isolation canary — runs inside your analysis VM and screams the instant the outside world becomes reachable, so you never forget to re-disable the adapter. Cross-platform; native OS popup on Windows.',
    cli: ['cargo run -p FuckAroundFindOut', '', '# Also watch a host-only adapter, twice a second', 'cargo run -p FuckAroundFindOut -- --target 192.168.56.1:445 --interval-ms 500'],
    prefixes: [['SAFE', 'Isolated — no connectivity (heartbeat)'], ['ALERT', 'The outside world is reachable right now']],
  },
  {
    id: 'flushot', icon: '💉', name: 'FluShot', group: 'Malware analysis',
    blurb: 'Encrypted sample vault — downloads samples itself (no browser, so no SmartScreen) and writes only ChaCha20-Poly1305 ciphertext, so AV never sees them. Decrypt inside your VM.',
    cli: ['# Fetch straight to ciphertext', 'cargo run -p FluShot -- fetch https://.../sample', '', '# Decrypt (inside your VM)', 'cargo run -p FluShot -- open vault/sample.enc --out ./work'],
    prefixes: [['FETCH', 'Started a download'], ['SAVED', 'Encrypted into the vault'], ['OPENED', 'Decrypted back to a file'], ['KEY', 'A new vault key was generated']],
  },
  {
    id: 'humptydumpty', icon: '🥚', name: 'HumptyDumpty', group: 'Malware analysis',
    blurb: 'Static malware triage — cracks a sample open into hashes/imphash, PE/ELF facts, per-section entropy, suspicious imports, and carved IOCs. Reads it, never runs it.',
    cli: ['cargo run -p HumptyDumpty -- ./suspicious.exe', 'cargo run -p HumptyDumpty -- --strings sample.dll'],
    prefixes: [['HASH', 'md5 / sha256 / imphash'], ['SECTION', 'A section with its size and entropy'], ['IMPORT', 'A suspicious API import + category'], ['IOC', 'Carved url / ip / domain / email / regkey'], ['ALERT', 'High-entropy section or capability-rich profile']],
  },
];

function toolById(id) {
  return TOOLS.find((t) => t.id === id) || null;
}

// Build a <pre class="code"> from lines; lines starting with '#' render muted.
function codeBlock(lines) {
  const pre = document.createElement('pre');
  pre.className = 'code';
  lines.forEach((line, i) => {
    if (line.startsWith('#')) {
      const span = document.createElement('span');
      span.className = 'comment';
      span.textContent = line;
      pre.appendChild(span);
    } else {
      pre.appendChild(document.createTextNode(line));
    }
    if (i < lines.length - 1) pre.appendChild(document.createTextNode('\n'));
  });
  return pre;
}

function localCta() {
  const box = document.createElement('div');
  box.className = 'local-cta';
  const h = document.createElement('h2');
  h.textContent = '🔒 Runs locally only';
  const p = document.createElement('p');
  p.textContent = 'This tool is part of the Rusty Toolz dashboard, which binds to localhost and never accepts remote connections — several tools scan networks, capture packets, or handle live malware. To use it, clone the repo and run the installer on your own machine:';
  const code = codeBlock([
    'git clone ' + REPO_URL,
    'cd rusty-tools',
    '',
    '# Linux / macOS:',
    './install.sh',
    '',
    '# Windows (PowerShell):',
    'powershell -ExecutionPolicy Bypass -File .\\install.ps1',
  ]);
  const p2 = document.createElement('p');
  p2.style.margin = '0';
  p2.textContent = 'The installer checks for prerequisites (Rust and the platform build tools) and installs only what’s missing, optionally adds a rustytoolz.local alias, builds, and opens the dashboard at http://localhost. (Several tools are Linux-only.)';
  box.append(h, p, code, p2);
  return box;
}

// --- landing grid (index.html) ---
function renderIndex(root) {
  GROUPS.forEach((group) => {
    const section = document.createElement('section');
    section.className = 'tool-group';
    const header = document.createElement('h2');
    header.className = 'tool-group-header';
    header.textContent = group;
    const grid = document.createElement('div');
    grid.className = 'tool-grid';
    TOOLS.filter((t) => t.group === group).forEach((t) => {
      const card = document.createElement('a');
      card.className = 'tool-card';
      card.href = 'tool.html?id=' + encodeURIComponent(t.id);
      const icon = document.createElement('span');
      icon.className = 'tool-icon';
      icon.textContent = t.icon;
      const name = document.createElement('h2');
      name.textContent = t.name;
      const blurb = document.createElement('p');
      blurb.textContent = t.blurb;
      card.append(icon, name, blurb);
      grid.appendChild(card);
    });
    section.append(header, grid);
    root.appendChild(section);
  });
}

// --- tool detail (tool.html) ---
function renderTool(root) {
  const id = new URLSearchParams(location.search).get('id');
  const tool = toolById(id);
  if (!tool) {
    const p = document.createElement('p');
    p.textContent = 'Unknown tool. ';
    const a = document.createElement('a');
    a.href = 'index.html';
    a.textContent = 'Back to all tools';
    p.appendChild(a);
    root.appendChild(p);
    return;
  }
  document.title = tool.name + ' — Rusty Toolz';

  const head = document.createElement('div');
  head.className = 'detail-head';
  const icon = document.createElement('span');
  icon.className = 'tool-icon';
  icon.textContent = tool.icon;
  const h1 = document.createElement('h1');
  h1.textContent = tool.name;
  head.append(icon, h1);

  const group = document.createElement('div');
  group.className = 'detail-group';
  group.textContent = tool.group;

  const blurb = document.createElement('p');
  blurb.className = 'detail-blurb';
  blurb.textContent = tool.blurb;

  root.append(head, group, blurb, localCta());

  const usageLabel = document.createElement('div');
  usageLabel.className = 'section-label';
  usageLabel.textContent = 'Command-line usage';
  root.append(usageLabel, codeBlock(tool.cli));

  if (tool.prefixes && tool.prefixes.length) {
    const pfxLabel = document.createElement('div');
    pfxLabel.className = 'section-label';
    pfxLabel.textContent = 'Output line prefixes';
    const table = document.createElement('table');
    table.className = 'prefix-table';
    tool.prefixes.forEach(([code, meaning]) => {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td');
      td1.textContent = code;
      const td2 = document.createElement('td');
      td2.textContent = meaning;
      tr.append(td1, td2);
      table.appendChild(tr);
    });
    root.append(pfxLabel, table);
  }
}

function renderFooter() {
  const footer = document.createElement('footer');
  footer.className = 'site-footer';
  const repo = document.createElement('a');
  repo.href = 'https://github.com/denvercoder/rusty-tools';
  repo.target = '_blank';
  repo.rel = 'noopener';
  repo.textContent = 'github.com/denvercoder/rusty-tools';
  const email = document.createElement('a');
  email.href = 'mailto:support@rustytoolz.com';
  email.textContent = 'support@rustytoolz.com';
  footer.append(repo, email);
  document.body.appendChild(footer);
}

document.addEventListener('DOMContentLoaded', () => {
  const grid = document.getElementById('grid');
  const detail = document.getElementById('detail');
  if (grid) renderIndex(grid);
  if (detail) renderTool(detail);
  renderFooter();
});
