#!/usr/bin/env node
/**
 * Build / verify the HyxAPI check-in module.
 *
 * `src/hyx_checkin.js` is the source of truth. Surge cannot read from src/, so the
 * build copies it to `hyx_checkin.js` in the repository root, which is the file the
 * module's `script-path` points at:
 *
 *   https://raw.githubusercontent.com/Suk1u/HyxCheckin/main/hyx_checkin.js
 *
 * Usage:
 *   node scripts/build-hyx.js            # copy src/ -> root artifact
 *   node scripts/build-hyx.js --check    # verify module <-> script consistency
 *   node scripts/build-hyx.js --check --url https://cdn.jsdelivr.net/gh/.../hyx_checkin.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const SRC_JS = path.join(ROOT, 'src', 'hyx_checkin.js');
const OUT_JS = path.join(ROOT, 'hyx_checkin.js');
const MODULE = path.join(ROOT, 'HyxCheckin.sgmodule');

const SCRIPT_NAME = 'hyx_checkin.js';
const EXPECTED_RAW = 'https://raw.githubusercontent.com/Suk1u/HyxCheckin/main/' + SCRIPT_NAME;

/* Script types the module declares; the JS must dispatch all of them.
   Two http-response lines are expected: the body-reading capture on login/refresh,
   plus a header-only fallback so third-party (OAuth) logins are captured too. */
const REQUIRED_TYPES = { 'http-response': 2, cron: 1, generic: 1 };

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { out[key] = next; i += 1; }
      else out[key] = true;
    }
  }
  return out;
}

function scriptLines(module) {
  const lines = [];
  let section = '';
  module.split(/\r?\n/).forEach(function (raw) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const header = /^\[(.+)\]$/.exec(line);
    if (header) { section = header[1]; return; }
    if (section === 'Script') lines.push(line);
  });
  return lines;
}

function declarations(module) {
  const match = /^#!arguments=(.*)$/m.exec(module);
  if (!match) return [];
  return match[1].split(',').map(function (item) {
    const idx = item.indexOf(':');
    return (idx < 0 ? item : item.slice(0, idx)).trim();
  }).filter(Boolean);
}

function check(module, script, expectedRaw) {
  const problems = [];
  const warnings = [];
  const lines = scriptLines(module);
  const expectedCount = Object.keys(REQUIRED_TYPES)
    .reduce(function (sum, k) { return sum + REQUIRED_TYPES[k]; }, 0);

  /* 1. every [Script] line must point at the same, expected JS */
  const paths = lines.map(function (line) {
    const m = /script-path=([^,\s]+)/.exec(line);
    return m ? m[1] : '';
  });
  if (paths.length !== expectedCount) {
    problems.push('expected ' + expectedCount + ' [Script] lines, found ' + paths.length);
  }
  if (paths.some(function (p) { return !p; })) {
    problems.push('a [Script] line has no script-path');
  }
  if (new Set(paths).size > 1) {
    problems.push('all [Script] lines must share one script-path, got: ' + paths.join(' | '));
  }
  if (paths[0] && paths[0] !== expectedRaw) {
    problems.push('script-path is ' + paths[0] + '\n         expected ' + expectedRaw);
  }
  if (paths[0] && !paths[0].endsWith('/' + SCRIPT_NAME)) {
    problems.push('script-path must end with /' + SCRIPT_NAME);
  }

  /* 2. declared types must be present in the module and dispatched in the JS */
  Object.keys(REQUIRED_TYPES).forEach(function (type) {
    const found = lines.filter(function (line) {
      return new RegExp('(?:^|[=,])\\s*type=' + type + '(?:,|$)').test(line);
    }).length;
    if (found !== REQUIRED_TYPES[type]) {
      problems.push('expected ' + REQUIRED_TYPES[type] + ' type=' + type +
        ' [Script] line(s), found ' + found);
    }
    if (script.indexOf('"' + type + '"') === -1) {
      problems.push('script never dispatches type=' + type);
    }
  });

  /* 3. placeholders <-> #!arguments */
  const declared = declarations(module);
  const used = new Set();
  const re = /\{\{\{([A-Za-z0-9_]+)\}\}\}/g;
  let m;
  while ((m = re.exec(module))) used.add(m[1]);
  used.forEach(function (name) {
    if (declared.indexOf(name) === -1) {
      problems.push('placeholder {{{' + name + '}}} is not declared in #!arguments');
    }
  });
  declared.forEach(function (name) {
    if (!used.has(name)) warnings.push('argument ' + name + ' is declared but never used');
  });

  /* 4. the body-reading capture line must preserve duplicate Set-Cookie fields;
        the header-only fallback deliberately does NOT use full-header-mode so it
        still works on a Surge build that does not know the parameter. */
  lines.filter(function (line) { return /type=http-response/.test(line); })
    .forEach(function (capture, index) {
      const label = 'capture line #' + (index + 1);
      const readsBody = /requires-body=true/.test(capture);
      if (readsBody && !/full-header-mode=true/.test(capture)) {
        problems.push(label + ' needs full-header-mode=true, otherwise duplicate Set-Cookie is lost');
      }
      if (!/timeout=\d+/.test(capture)) problems.push(label + ' needs an explicit timeout');
      if (readsBody && !/max-size=\d+/.test(capture)) {
        problems.push(label + ' buffers the body and needs an explicit max-size');
      }
    });
  if (!lines.some(function (line) { return /type=http-response/.test(line) && /requires-body=true/.test(line); })) {
    problems.push('the login/refresh capture line needs requires-body=true to read the token bundle');
  }

  /* 5. the narrow capture line must be listed before the broad fallback one */
  const responseLines = lines.filter(function (line) { return /type=http-response/.test(line); });
  if (responseLines.length === 2 && !/api\\\/user/.test(responseLines[0])) {
    problems.push('the narrow (login/refresh) capture line must come before the fallback line');
  }

  /* 6. cron line must wake the system and allow enough time */
  const cron = lines.find(function (line) { return /type=cron/.test(line); });
  if (cron) {
    if (!/cronexp="[^"]+"/.test(cron)) problems.push('cron line needs a quoted cronexp');
    if (!/wake-system=true/.test(cron)) warnings.push('cron line without wake-system=true may not run while asleep');
    const t = /timeout=(\d+)/.exec(cron);
    if (!t || Number(t[1]) < 60) problems.push('cron timeout should be >= 60s, got ' + (t ? t[1] : 'none'));
  }

  /* 7. MITM host must match the default BASE_URL */
  if (!/^hostname\s*=\s*%APPEND%\s*\{\{\{MITM_HOST\}\}\}/m.test(module)) {
    problems.push('[MITM] must be `hostname = %APPEND% {{{MITM_HOST}}}`');
  }
  const baseArg = /BASE_URL:([^,\s]+)/.exec(module);
  const mitmArg = /MITM_HOST:([^,\s]+)/.exec(module);
  if (baseArg && mitmArg && baseArg[1] !== mitmArg[1]) {
    problems.push('BASE_URL (' + baseArg[1] + ') and MITM_HOST (' + mitmArg[1] + ') must match');
  }

  /* 8. no debug=true on a remote script-path (Surge re-downloads every run) */
  if (lines.some(function (line) { return /debug=true/.test(line); })) {
    problems.push('debug=true on a remote script-path breaks tasks on a network hiccup');
  }

  /* 9. the JS must still know the endpoints it claims to use */
  ['/api/user/checkin', '/api/user/auth/refresh', '/api/user/login', '/api/user/self']
    .forEach(function (p) {
      if (script.indexOf(p) === -1) problems.push('script no longer references ' + p);
    });

  return { problems, warnings, lines: lines.length, paths: paths };
}

function sha(text) {
  return crypto.createHash('sha256').update(text).digest('hex').slice(0, 12);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const script = fs.readFileSync(SRC_JS, 'utf8');
  const module = fs.readFileSync(MODULE, 'utf8');
  const expectedRaw = typeof args.url === 'string' ? args.url : EXPECTED_RAW;

  if (args.check) {
    const report = check(module, script, expectedRaw);

    /* the root artifact is what Surge downloads — it must match src/ exactly */
    if (!fs.existsSync(OUT_JS)) {
      report.problems.push('hyx_checkin.js is missing; run `node scripts/build-hyx.js`');
    } else if (fs.readFileSync(OUT_JS, 'utf8') !== script) {
      report.problems.push('hyx_checkin.js is out of date with src/hyx_checkin.js; ' +
        'run `node scripts/build-hyx.js`');
    }

    console.log('src sha256   : ' + sha(script));
    console.log('[Script] lines: ' + report.lines);
    console.log('script-path  : ' + (report.paths[0] || '(none)'));
    report.warnings.forEach(function (w) { console.log('  warn  ' + w); });
    report.problems.forEach(function (p) { console.log('  ERROR ' + p); });
    console.log(report.problems.length
      ? '\n' + report.problems.length + ' problem(s)'
      : '\n0 problem(s)');
    process.exit(report.problems.length ? 1 : 0);
  }

  fs.writeFileSync(OUT_JS, script, 'utf8');
  console.log('wrote ' + path.relative(ROOT, OUT_JS) + '  (sha256 ' + sha(script) + ')');
  console.log('surge fetches it from ' + expectedRaw);
}

main();
