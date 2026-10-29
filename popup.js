const toggle = document.getElementById('enabled');
const status = document.getElementById('status');

chrome.storage.local.get({ phishyphishEnabled: true, phishyphishLast: null }, (r) => {
  toggle.checked = r.phishyphishEnabled !== false;
  render(r.phishyphishLast);
});

toggle.addEventListener('change', () => {
  chrome.storage.local.set({ phishyphishEnabled: toggle.checked });
});

chrome.storage.onChanged.addListener((ch) => {
  if (ch.phishyphishLast) render(ch.phishyphishLast.newValue);
});

function render(last) {
  if (!last || !last.ts) {
    status.className = '';
    status.textContent = 'Open an email in Gmail to scan it.';
    return;
  }
  const label = last.verdict === 'dangerous' ? 'Phishing likely'
              : last.verdict === 'suspicious' ? 'Suspicious email'
              : 'No strong signals';
  status.className = last.verdict;
  status.innerHTML =
    `<b>${label} — risk ${last.score}/100</b>` +
    `${last.findings} signal(s)<br>` +
    `From: ${escapeHtml(last.sender || 'unknown')}<br>` +
    `${escapeHtml((last.subject || '').slice(0, 60))}`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}