// Shared log-panel rendering, used by every tool page. Centralized here
// (rather than duplicated per page) specifically so the one safety-critical
// rule lives in one place: several tools print lines built from
// externally-controlled input (a honeypot's DATA line echoes whatever bytes
// a connecting client sent; an SSH brute-force line includes the attempted
// username) — that content must never be parsed as HTML. Severity is
// classified only from a line's fixed, known prefix; the line itself is
// always written via `textContent`, never `innerHTML`, so nothing in it can
// ever execute.

// Ordered so the first matching pattern wins.
const SEVERITY_PATTERNS = [
  [/^ALERT\b/, 'sev-danger'],
  [/^FAIL\b/, 'sev-danger'],
  [/^REMOVED\b/, 'sev-danger'],
  [/^WARN\b/, 'sev-warn'],
  [/^MODIFIED\b/, 'sev-warn'],
  [/^LOGIN\s+fail\b/, 'sev-warn'],
  [/^SUDO\s+fail\b/, 'sev-warn'],
  [/^SKIP\b/, 'sev-muted'],
  [/^DATA\b/, 'sev-muted'],
  [/^PASS\b/, 'sev-ok'],
  [/^ADDED\b/, 'sev-ok'],
  [/^LOGIN\s+ok\b/, 'sev-ok'],
  [/^PORT \d+ is Open/, 'sev-ok'],
  [/^Baseline created/, 'sev-ok'],
  [/^(CONN|SUDO|HTTP|DNS|TCP|UDP|ICMP|ARP)\b/, 'sev-info'],
];

function severityClass(line) {
  for (const [pattern, cls] of SEVERITY_PATTERNS) {
    if (pattern.test(line)) return cls;
  }
  return null;
}

/**
 * Appends one line to a log-panel container as its own element, colored by
 * severity where recognized, and scrolls the panel to follow it. Always
 * safe against HTML/script injection in `line` — see the note above.
 */
function appendLine(container, line) {
  const el = document.createElement('div');
  const cls = severityClass(line);
  if (cls) el.className = cls;
  el.textContent = line;
  container.appendChild(el);
  container.scrollTop = container.scrollHeight;
}

function clearPanel(container) {
  container.replaceChildren();
}
