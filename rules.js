/* PhishGuard detection engine — no DOM, no network, pure functions. */
var PhishGuardRules = (function () {
  'use strict';

  /* ---------- reference data ---------- */

  const FREE_PROVIDERS = new Set([
    'gmail.com','googlemail.com','yahoo.com','yahoo.co.uk','ymail.com','rocketmail.com',
    'outlook.com','hotmail.com','live.com','msn.com','aol.com','icloud.com','me.com','mac.com',
    'proton.me','protonmail.com','gmx.com','gmx.net','mail.com','yandex.com','yandex.ru',
    'zoho.com','tutanota.com','hey.com','fastmail.com'
  ]);

  const SUSPICIOUS_TLDS = new Set([
    'tk','ml','ga','cf','gq','zip','mov','top','xyz','click','link','country','stream','download',
    'review','win','bid','loan','work','men','party','racing','science','accountant','faith',
    'cricket','date','trade','webcam','gdn','icu','rest','surf','bar','cam','monster','quest',
    'cyou','sbs','buzz','lol','mom','hair','beauty','makeup','skin','fit','cfd','boutique'
  ]);

  const SHORTENERS = new Set([
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly','cutt.ly',
    'shorturl.at','rb.gy','tiny.cc','t.ly','shorte.st','adf.ly','bl.ink','lnkd.in','s.id',
    'v.gd','qr.ae','shorturl.com','clck.ru','cutt.us'
  ]);

  const BRANDS = [
    { name:'paypal',       domains:['paypal.com','paypal.me','paypalobjects.com'] },
    { name:'apple',        domains:['apple.com','icloud.com','me.com'] },
    { name:'microsoft',    domains:['microsoft.com','live.com','outlook.com','office.com','office365.com','microsoftonline.com','sharepoint.com'] },
    { name:'google',       domains:['google.com','gmail.com','youtube.com','googlemail.com','googleapis.com'] },
    { name:'amazon',       domains:['amazon.com','amazon.co.uk','amazon.in','amazon.de','amazonaws.com','a.co'] },
    { name:'netflix',      domains:['netflix.com'] },
    { name:'facebook',     domains:['facebook.com','fb.com','meta.com'] },
    { name:'instagram',    domains:['instagram.com'] },
    { name:'whatsapp',     domains:['whatsapp.com'] },
    { name:'linkedin',     domains:['linkedin.com'] },
    { name:'twitter',      domains:['twitter.com','x.com'] },
    { name:'dropbox',      domains:['dropbox.com'] },
    { name:'docusign',     domains:['docusign.com','docusign.net'] },
    { name:'zoom',         domains:['zoom.us'] },
    { name:'steam',        domains:['steampowered.com','steamcommunity.com'] },
    { name:'coinbase',     domains:['coinbase.com'] },
    { name:'binance',      domains:['binance.com'] },
    { name:'metamask',     domains:['metamask.io'] },
    { name:'chase',        domains:['chase.com'] },
    { name:'bankofamerica',domains:['bankofamerica.com'] },
    { name:'wellsfargo',   domains:['wellsfargo.com'] },
    { name:'citibank',     domains:['citibank.com','citi.com'] },
    { name:'hsbc',         domains:['hsbc.com'] },
    { name:'barclays',     domains:['barclays.co.uk','barclays.com'] },
    { name:'hdfc',         domains:['hdfcbank.com'] },
    { name:'icici',        domains:['icicibank.com'] },
    { name:'dhl',          domains:['dhl.com'] },
    { name:'fedex',        domains:['fedex.com'] },
    { name:'ups',          domains:['ups.com'] },
    { name:'usps',         domains:['usps.com'] },
    { name:'irs',          domains:['irs.gov'] }
  ];

  const MULTI_SUFFIX = new Set([
    'co.uk','org.uk','ac.uk','gov.uk','me.uk','com.au','net.au','org.au','edu.au','co.nz',
    'co.in','net.in','org.in','co.jp','ne.jp','or.jp','com.br','com.mx','com.ar','com.co',
    'com.tr','com.sg','com.hk','com.tw','com.cn','co.kr','co.za','com.ng','com.pk','com.sa',
    'com.eg','co.il','com.my','com.ph','com.vn','com.pe','com.ec','com.uy'
  ]);

  const EXEC_EXT = new Set(['exe','scr','js','jse','vbs','vbe','bat','cmd','com','pif','jar',
    'hta','msi','lnk','iso','img','vhd','vhdx','ps1','psm1','reg','wsf','wsh','cpl','scf',
    'inf','gadget','apk','dmg','app','application','chm','url']);
  const MACRO_EXT = new Set(['docm','xlsm','pptm','dotm','xlam','xltm','potm','ppam']);
  const WEB_EXT   = new Set(['html','htm','xhtml','svg','mht','mhtml']);
  const ARCH_EXT  = new Set(['zip','rar','7z','tar','gz','cab','ace']);

  /* ---------- helpers ---------- */

  function registrableDomain(host) {
    if (!host) return '';
    host = String(host).toLowerCase().replace(/\.$/, '');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.indexOf(':') !== -1) return host;
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const last2 = parts.slice(-2).join('.');
    if (MULTI_SUFFIX.has(last2)) return parts.slice(-3).join('.');
    return last2;
  }

  function levenshtein(a, b) {
    if (a === b) return 0;
    const m = a.length, n = b.length;
    if (!m) return n; if (!n) return m;
    let prev = new Array(n + 1);
    for (let j = 0; j <= n; j++) prev[j] = j;
    for (let i = 1; i <= m; i++) {
      let cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[n];
  }

  function extractDomainFromText(text) {
    if (!text) return null;
    const m = text.match(/\b((?:https?:\/\/)?(?:[\w-]+\.)+[a-z]{2,})(?::\d+)?(?:[\/?#]\S*)?/i);
    if (!m) return null;
    const d = m[1].replace(/^https?:\/\//i, '').toLowerCase();
    if (!/\.[a-z]{2,}$/i.test(d)) return null;
    return { domain: d, reg: registrableDomain(d) };
  }

  /* ---------- sender checks ---------- */

  function checkSender(email, add) {
    const senderEmail = String(email.senderEmail || '').trim().toLowerCase();
    const senderName  = String(email.senderName  || '').trim();

    if (!senderEmail) { add('low', 'Sender', 'Could not determine the sender address', 2); return; }

    const at = senderEmail.lastIndexOf('@');
    if (at < 0) return;
    const host = senderEmail.slice(at + 1).replace(/^\[|\]$/g, '');
    if (!host) return;

    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const reg  = registrableDomain(host);
    const labels = host.split('.');
    const tld = labels[labels.length - 1];

    if (isIp) add('high', 'Sender', `Sender address is a raw IP address (${host})`, 30);
    if (host.indexOf('xn--') !== -1)
      add('high', 'Sender', `Sender domain uses punycode ("${host}") — typical of homoglyph attacks`, 20);
    if (!isIp && SUSPICIOUS_TLDS.has(tld))
      add('medium', 'Sender', `Sender uses a high-abuse TLD (.${tld})`, 10);
    if (labels.length >= 5)
      add('low', 'Sender', 'Sender host has an unusual number of subdomains', 4);

    if (!isIp) {
      for (const b of BRANDS) {
        const official = b.domains.some(d => reg === d || host === d || host.endsWith('.' + d));
        if (official) break;

        if (host.indexOf(b.name) !== -1) {
          add('high', 'Sender',
            `Sender domain "${reg}" contains "${b.name}" but is not an official ${b.name} domain`, 30);
          break;
        }
        if (new RegExp('\\b' + b.name + '\\b', 'i').test(senderName)) {
          const via = FREE_PROVIDERS.has(reg) ? ` — sent from a free ${reg} mailbox` : '';
          add('high', 'Sender',
            `Display name claims to be "${b.name}" but the sending domain is "${reg}"${via}`, 30);
          break;
        }
        const sld = reg.split('.')[0];
        let hit = false;
        for (const d of b.domains) {
          const base = d.split('.')[0];
          if (base === sld) continue;
          if (Math.abs(base.length - sld.length) <= 2) {
            const dist = levenshtein(base, sld);
            if (dist > 0 && dist <= 2 && !FREE_PROVIDERS.has(reg)) {
              add('high', 'Sender',
                `Sender domain "${reg}" is ${dist} character(s) away from "${d}" (typosquatting)`, 28);
              hit = true;
            }
          }
        }
        if (hit) break;
      }
    }

    // Display name showing a different address / domain
    const mEmail = senderName.match(/[\w.+-]+@([\w.-]+\.[a-z]{2,})/i);
    if (mEmail) {
      if (mEmail[0].toLowerCase() !== senderEmail)
        add('medium', 'Sender',
          `Display name shows "${mEmail[0]}" but the real sender is "${senderEmail}"`, 16);
    } else {
      const mDom = senderName.match(/\b((?:[\w-]+\.)+[a-z]{2,})\b/i);
      if (mDom && !isIp) {
        const named = mDom[1].toLowerCase();
        if (registrableDomain(named) !== reg)
          add('medium', 'Sender',
            `Display name shows the domain "${named}" but the email comes from "${reg}"`, 16);
      }
    }
  }

  /* ---------- link checks ---------- */

  function checkLinks(links, add) {
    const issues = [];
    for (const l of links) {
      const raw = String(l.href || '').trim();
      if (!raw || raw.charAt(0) === '#' || /^(mailto|tel|sms):/i.test(raw)) continue;

      let u;
      try { u = new URL(raw); } catch (e) { continue; }

      const proto = u.protocol.toLowerCase();
      const text  = String(l.text || '').trim();

      if (proto === 'javascript:' || proto === 'data:' || proto === 'blob:') {
        issues.push({ w: 30, msg: `Link uses a "${proto}" URL instead of a web address` });
        continue;
      }
      if (proto !== 'http:' && proto !== 'https:') continue;

      const host = u.hostname.toLowerCase();
      const reg  = registrableDomain(host);
      const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

      if (u.username || u.password)
        issues.push({ w: 30, msg: `Link disguises its destination with an "@" (real host: ${host})` });

      if (isIp)
        issues.push({ w: 22, msg: `Link points to a raw IP address (${host})` });

      if (host.indexOf('xn--') !== -1)
        issues.push({ w: 18, msg: `Link uses a punycode domain (${host})` });

      if (SHORTENERS.has(reg) || SHORTENERS.has(host))
        issues.push({ w: 12, msg: `Link is shortened (${host}) and hides where it goes` });

      const tld = host.split('.').pop();
      if (SUSPICIOUS_TLDS.has(tld))
        issues.push({ w: 10, msg: `Link uses a high-abuse TLD (.${tld})` });

      if (proto === 'http:')
        issues.push({ w: 4, msg: `Link is not HTTPS (${host})` });

      for (const b of BRANDS) {
        const official = b.domains.some(d => reg === d || host === d || host.endsWith('.' + d));
        if (official) break;
        if (host.indexOf(b.name) !== -1) {
          issues.push({ w: 28, msg: `Link mentions "${b.name}" in "${host}" but actually goes to "${reg}"` });
          break;
        }
      }

      const shown = extractDomainFromText(text);
      if (shown && shown.reg && shown.reg !== reg) {
        issues.push({ w: 28, msg: `Link text shows "${shown.reg}" but the link goes to "${reg}"` });
      }

      if (host.length > 60 || host.split('.').length > 5)
        issues.push({ w: 5, msg: `Link host is unusually long or deeply nested (${host})` });
    }

    issues.sort((a, b) => b.w - a.w);
    const seen = new Set();
    let shown = 0;
    for (const i of issues) {
      if (seen.has(i.msg)) continue;
      seen.add(i.msg);
      add(i.w >= 20 ? 'high' : i.w >= 10 ? 'medium' : 'low', 'Link', i.msg, i.w);
      if (++shown >= 6) break;
    }
    if (issues.length > shown)
      add('low', 'Link', `${issues.length - shown} additional link warning(s) not shown`, 2);
  }

  /* ---------- content checks ---------- */

  const TEXT_RULES = [
    { id:'urgency', w:7,  re:/\b(urgent(ly)?|immediately|right away|as soon as possible|within (?:the next )?\d+ (?:hours?|minutes?|days?)|final (?:warning|notice)|last chance|act now|expires? (?:today|soon)|time[-\s]?sensitive)\b/gi },
    { id:'threat',  w:9,  re:/\b(suspend(?:ed|sion)?|terminat(?:e|ed|ion)|deactivat(?:e|ed)|locked out|account (?:will be|has been) (?:closed|limited|restricted|suspended)|unauthori[sz]ed (?:access|login|activity)|unusual activity|legal action)\b/gi },
    { id:'credentials', w:11, re:/\b(password|passcode|one[-\s]?time (?:code|password)|otp|verification code|2fa|two[-\s]?factor|social security(?: number)?|ssn|credit card (?:number|details)|cvv|date of birth|mother'?s maiden name|seed phrase|recovery phrase|api key)\b/gi },
    { id:'verify',  w:9,  re:/\b(verif(?:y|ication of) your (?:account|identity|email|information|details)|confirm your (?:account|identity|details|password)|update your (?:payment|billing|account) (?:information|details)|re[-\s]?authenticate|validate your account|unlock your account)\b/gi },
    { id:'reward',  w:7,  re:/\b(congratulations|you(?:'ve| have) won|you are a winner|claim your (?:prize|reward|gift)|free gift|gift card|lottery|selected as a winner)\b/gi },
    { id:'finance', w:7,  re:/\b(wire transfer|bank transfer|invoice (?:attached|due)|payment (?:failed|declined)|billing (?:problem|issue)|refund (?:pending|available)|outstanding balance|past due|remittance)\b/gi },
    { id:'generic', w:5,  re:/\b(dear (?:customer|user|client|sir|madam|account holder|member)|valued customer|dear friend)\b/gi },
    { id:'secrecy', w:8,  re:/\b(do not (?:share|disclose|tell)|keep this (?:confidential|secret)|this is a (?:confidential|private) (?:message|communication))\b/gi },
    { id:'clickbait', w:5, re:/\b(click here|click below|click the link|follow this link|log ?in here|sign ?in here)\b/gi }
  ];

  function checkText(email, linkCount, add) {
    const text = String(email.bodyText || '').replace(/\s+/g, ' ');
    const html = String(email.bodyHtml || '');

    if (!text) return;

    const hits = {};
    for (const r of TEXT_RULES) {
      const raw = text.match(r.re) || [];
      const uniq = new Set(raw.map(x => x.toLowerCase()));
      if (!uniq.size) continue;
      hits[r.id] = true;
      const w = r.w + Math.min(uniq.size - 1, 3) * 2;
      add(w >= 9 ? 'high' : 'medium', 'Content',
        `Phishing language: ${r.id} (${Array.from(uniq).slice(0, 3).join(', ')})`, w);
    }

    // Combination rule — the classic "act now + log in + click" pattern
    const pressure = hits.urgency || hits.threat || hits.secrecy;
    const creds    = hits.credentials || hits.verify;
    if (pressure && creds && linkCount > 0) {
      add('high', 'Content',
        'Email combines pressure tactics with a credential/verification request and an external link', 16);
    }

    // Deliberate misspellings used to evade filters
    const typo = text.match(/\b(verifiy|verfy|verfiy|acount|acccount|recieve|recieved|reciept|updat(?:e|ing) informations?|paypa1|paypall|micros0ft|microsft|app1e|amaz0n|goog1e|netfl1x|bankofamer1ca|infomation|suspeneded|immediatly|clickhear)\b/gi);
    if (typo && typo.length) {
      add('medium', 'Content',
        `Contains deliberate misspellings: ${Array.from(new Set(typo.map(t => t.toLowerCase()))).slice(0, 4).join(', ')}`, 12);
    }

    // Formatting anomalies
    const words = text.split(/\s+/).filter(w => w.length > 3);
    if (words.length > 25) {
      const caps = words.filter(w => w === w.toUpperCase() && /[A-Z]/.test(w)).length;
      if (caps / words.length > 0.25) add('low', 'Content', 'High proportion of ALL-CAPS words', 4);
    }
    if ((text.match(/!/g) || []).length >= 5) add('low', 'Content', 'Excessive exclamation marks', 3);

    // Password field smuggled into the email
    if (/<input[^>]+type\s*=\s*["']?password/i.test(html)) {
      add('high', 'Content', 'Email body contains a password input field', 30);
    }

    // Links hidden with inline CSS
    if (email.hiddenLinkCount > 0) {
      add('high', 'Content', `${email.hiddenLinkCount} link(s) hidden with CSS (display:none / font-size:0)`, 15);
    }
  }

  /* ---------- attachment checks ---------- */

  function checkAttachments(names, add) {
    for (const raw of names) {
      const name = String(raw || '').trim();
      if (!name) continue;
      const parts = name.toLowerCase().split('.');
      if (parts.length < 2) continue;
      const ext = parts[parts.length - 1];

      if (EXEC_EXT.has(ext)) {
        add('high', 'Attachment', `Executable attachment: ${name}`, 30);
      } else if (MACRO_EXT.has(ext)) {
        add('high', 'Attachment', `Macro-enabled document: ${name}`, 25);
      } else if (WEB_EXT.has(ext)) {
        add('medium', 'Attachment', `HTML/SVG attachment can host a fake login page: ${name}`, 14);
      } else if (ARCH_EXT.has(ext)) {
        add('low', 'Attachment', `Archive attachment — check contents before opening: ${name}`, 5);
      } else if (parts.length >= 3 && EXEC_EXT.has(parts[parts.length - 2])) {
        add('high', 'Attachment', `Double extension disguises an executable: ${name}`, 30);
      }
    }
  }

  /* ---------- main entry ---------- */

  function analyzeEmail(email) {
    const findings = [];
    const add = (level, category, message, weight) =>
      findings.push({ level, category, message, weight: Math.round(weight) });

    checkSender(email, add);
    checkLinks(email.links || [], add);
    checkText(email, (email.links || []).length, add);
    checkAttachments(email.attachments || [], add);

    const score = Math.min(100, findings.reduce((s, f) => s + f.weight, 0));
    let verdict = 'safe';
    if (score >= 30) verdict = 'dangerous';
    else if (score >= 10) verdict = 'suspicious';

    findings.sort((a, b) => b.weight - a.weight);
    return { score, verdict, findings };
  }

  return { analyzeEmail, registrableDomain };
})();