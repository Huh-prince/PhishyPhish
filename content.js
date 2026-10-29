(function () {
  'use strict';
  if (window.__phishguardLoaded) return;
  window.__phishguardLoaded = true;

  const HOST_ID = 'phishguard-host';
  let enabled = true;
  let lastKey = null;
  let timer = null;

  /* ---------------- boot ---------------- */

  try {
    chrome.storage.local.get({ phishguardEnabled: true }, (r) => {
      enabled = r.phishguardEnabled !== false;
      schedule();
    });
    chrome.storage.onChanged.addListener((ch) => {
      if (!ch.phishguardEnabled) return;
      enabled = ch.phishguardEnabled.newValue !== false;
      lastKey = null;
      if (enabled) schedule(); else removeBanner();
    });
  } catch (e) {
    enabled = true;
    schedule();
  }

  new MutationObserver(schedule).observe(document.documentElement, {
    childList: true, subtree: true
  });
  window.addEventListener('hashchange', () => { lastKey = null; schedule(); });

  /* ---------------- scheduling ---------------- */

  function schedule() {
    if (timer) return;
    timer = setTimeout(() => { timer = null; scan(); }, 450);
  }

  /* ---------------- DOM extraction ---------------- */

  function isVisible(el) {
    return !!el && el.getClientRects().length > 0 && el.offsetWidth > 0;
  }

  function getOpenMessage() {
    const bodies = Array.from(document.querySelectorAll('div.a3s')).filter(isVisible);
    if (!bodies.length) return null;
    const body = bodies[bodies.length - 1];              // newest message in thread
    const root = body.closest('div.adn') || body.closest('div.nH') || body.parentElement;
    return { body, root };
  }

  function extractSender(root) {
    let el = root.querySelector('span.gD[email]') || root.querySelector('[email][name]');
    if (el) {
      return {
        email: (el.getAttribute('email') || '').trim(),
        name:  (el.getAttribute('name') || el.textContent || '').trim()
      };
    }
    const any = root.querySelector('[email]');
    if (any) return { email: (any.getAttribute('email') || '').trim(), name: any.textContent.trim() };
    return { email: '', name: '' };
  }

  // Gmail wraps outbound links as https://www.google.com/url?q=<real>
  function unwrap(href) {
    try {
      const u = new URL(href, location.origin);
      if (/(^|\.)google\.com$/i.test(u.hostname) && u.pathname === '/url') {
        const q = u.searchParams.get('q') || u.searchParams.get('url');
        if (q) return q;
      }
    } catch (e) { /* ignore */ }
    return href;
  }

  function countHiddenLinks(body) {
    let n = 0;
    body.querySelectorAll('a[href]').forEach(a => {
      const style = (a.getAttribute('style') || '') + ' ' +
                    (a.parentElement && a.parentElement.getAttribute('style') || '');
      if (/display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0/i.test(style)) n++;
    });
    return n;
  }

  const FILENAME_RE = /^[\w\-. ()+]{1,80}\.[A-Za-z0-9]{2,5}$/;

  function extractAttachments(root) {
    const out = new Set();
    root.querySelectorAll('a[download]').forEach(a => {
      const n = a.getAttribute('download');
      if (n) out.add(n);
    });
    root.querySelectorAll('span.aV3, div.aQH span, [data-tooltip]').forEach(el => {
      const t = (el.getAttribute('data-tooltip') || el.textContent || '').trim();
      if (FILENAME_RE.test(t)) out.add(t);
    });
    return Array.from(out);
  }

  function extract(found) {
    const { body, root } = found;
    const sender  = extractSender(root);
    const subjectEl = root.querySelector('h2.hP') || document.querySelector('h2.hP');
    const subject = subjectEl ? subjectEl.textContent.trim() : '';

    const bodyText = (body.innerText || body.textContent || '').trim();
    const bodyHtml = body.innerHTML || '';

    const links = [];
    body.querySelectorAll('a[href]').forEach(a => {
      const href = unwrap(a.getAttribute('href') || '');
      if (!href) return;
      links.push({
        href,
        text: (a.innerText || a.textContent || '').trim().slice(0, 300)
      });
    });

    const attachments = extractAttachments(root);
    const hiddenLinkCount = countHiddenLinks(body);

    const key = [sender.email, subject, bodyText.length, bodyText.slice(0, 120),
                 links.length, attachments.join(',')].join('|');

    return {
      key,
      sender,
      subject,
      email: {
        senderEmail: sender.email,
        senderName: sender.name,
        subject,
        bodyText,
        bodyHtml,
        links,
        attachments,
        hiddenLinkCount
      }
    };
  }

  /* ---------------- scanning ---------------- */

  function scan() {
    if (!enabled) { removeBanner(); return; }
    if (document.hidden) return;

    const found = getOpenMessage();
    if (!found) { removeBanner(); return; }

    const data = extract(found);
    const existing = document.getElementById(HOST_ID);
    if (data.key === lastKey && existing) return;

    lastKey = data.key;
    const result = PhishGuardRules.analyzeEmail(data.email);
    render(found.body, data, result);
    saveLast(data, result);
  }

  /* ---------------- rendering ---------------- */

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  const COLORS = { dangerous: '#ef4444', suspicious: '#f59e0b', safe: '#10b981' };
  const LABELS = {
    dangerous:  'Phishing likely',
    suspicious: 'Suspicious email',
    safe:       'No strong phishing signals'
  };

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .wrap {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      font-size: 13px; line-height: 1.45; color: #1f2937;
      border: 1px solid #e5e7eb; border-left: 4px solid var(--c);
      border-radius: 8px; background: #ffffff; margin: 8px 0;
      box-shadow: 0 1px 2px rgba(0,0,0,.06);
      overflow: hidden;
    }
    .head {
      display: flex; align-items: center; gap: 8px;
      padding: 10px 12px; cursor: pointer; user-select: none;
      background: var(--bg);
    }
    .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--c); flex: 0 0 auto; }
    .title { font-weight: 600; color: var(--c); flex: 1 1 auto; }
    .score { font-size: 11px; color: #6b7280; font-variant-numeric: tabular-nums; }
    .chev { font-size: 11px; color: #6b7280; transition: transform .15s; }
    .wrap.collapsed .chev { transform: rotate(-90deg); }
    .body { padding: 4px 12px 12px; display: block; }
    .wrap.collapsed .body { display: none; }
    .row { display: flex; gap: 8px; padding: 5px 0; border-top: 1px solid #f3f4f6; align-items: flex-start; }
    .row:first-child { border-top: none; }
    .chip {
      flex: 0 0 auto; font-size: 10px; font-weight: 600; text-transform: uppercase;
      letter-spacing: .04em; padding: 2px 6px; border-radius: 4px;
      background: #f3f4f6; color: #4b5563; margin-top: 1px;
    }
    .chip.high { background: #fee2e2; color: #b91c1c; }
    .chip.medium { background: #fef3c7; color: #92400e; }
    .chip.low { background: #e0f2fe; color: #075985; }
    .msg { flex: 1 1 auto; word-break: break-word; }
    .meta { padding-top: 8px; font-size: 11px; color: #9ca3af; }
    .meta b { color: #6b7280; font-weight: 600; }
  `;

  function buildHtml(data, result) {
    const c = COLORS[result.verdict] || COLORS.safe;
    const bg = result.verdict === 'dangerous' ? '#fef2f2'
             : result.verdict === 'suspicious' ? '#fffbeb' : '#f0fdf4';
    const collapsed = result.verdict === 'safe' ? ' collapsed' : '';

    const rows = result.findings.slice(0, 10).map(f => `
      <div class="row">
        <span class="chip ${f.level}">${esc(f.category)}</span>
        <span class="msg">${esc(f.message)}</span>
      </div>`).join('');

    const sender = data.sender.email
      ? `${esc(data.sender.name || data.sender.email)} &lt;${esc(data.sender.email)}&gt;`
      : 'unknown sender';

    return `
      <style>${CSS}</style>
      <div class="wrap${collapsed}" style="--c:${c};--bg:${bg}">
        <div class="head" id="head">
          <span class="dot"></span>
          <span class="title">${LABELS[result.verdict]}</span>
          <span class="score">risk ${result.score}/100</span>
          <span class="chev">▾</span>
        </div>
        <div class="body">
          ${rows || '<div class="row"><span class="msg">No rule matched this message.</span></div>'}
          <div class="meta">
            From: <b>${sender}</b> · ${result.findings.length} signal(s) ·
            rule-based, runs locally
          </div>
        </div>
      </div>`;
  }

  function render(bodyEl, data, result) {
    const old = document.getElementById(HOST_ID);
    if (old) old.remove();

    const host = document.createElement('div');
    host.id = HOST_ID;
    host.style.cssText = 'all: initial; display: block;';
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = buildHtml(data, result);

    const head = shadow.getElementById('head');
    const wrap = shadow.querySelector('.wrap');
    if (head) head.addEventListener('click', () => wrap.classList.toggle('collapsed'));

    if (bodyEl.parentNode) bodyEl.parentNode.insertBefore(host, bodyEl);
    else bodyEl.insertAdjacentElement('beforebegin', host);
  }

  function removeBanner() {
    const el = document.getElementById(HOST_ID);
    if (el) el.remove();
  }

  function saveLast(data, result) {
    try {
      chrome.storage.local.set({
        phishguardLast: {
          verdict: result.verdict,
          score: result.score,
          subject: data.subject,
          sender: data.sender.email || data.sender.name,
          findings: result.findings.length,
          ts: Date.now()
        }
      });
    } catch (e) { /* ignore */ }
  }
})();