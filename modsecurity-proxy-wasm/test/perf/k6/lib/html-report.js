function metricValue(metrics, name, key) {
  const m = metrics[name];
  if (!m || !m.values) return null;
  const v = m.values[key];
  return v === undefined || v === null ? null : Number(v);
}

function fmtMs(v) {
  if (v === null || Number.isNaN(v)) return 'n/a';
  return `${v.toFixed(2)} ms`;
}

function fmtNum(v, digits = 0) {
  if (v === null || Number.isNaN(v)) return 'n/a';
  return v.toFixed(digits);
}

function fmtPct(v) {
  if (v === null || Number.isNaN(v)) return 'n/a';
  return `${(v * 100).toFixed(2)}%`;
}

function passBadge(ok) {
  return ok
    ? '<span class="badge pass">pass</span>'
    : '<span class="badge fail">fail</span>';
}

export function htmlReport(data, meta = {}) {
  const profile = meta.profile || __ENV.PERF_PROFILE || 'unknown';
  const scenario = meta.scenario || __ENV.PERF_SCENARIO || 'unknown';
  const metrics = data.metrics || {};
  const dur = 'http_req_duration';

  const p50 = metricValue(metrics, dur, 'med');
  const p90 = metricValue(metrics, dur, 'p(90)');
  const p95 = metricValue(metrics, dur, 'p(95)');
  const p99 = metricValue(metrics, dur, 'p(99)');
  const avg = metricValue(metrics, dur, 'avg');
  const rps = metricValue(metrics, 'http_reqs', 'rate');
  const reqs = metricValue(metrics, 'http_reqs', 'count');
  const failRate = metricValue(metrics, 'http_req_failed', 'rate');
  const checksRate = metricValue(metrics, 'checks', 'rate');
  const p99Threshold = Number(meta.p99_threshold_ms || __ENV.PERF_P99_MS || 200);
  const failThreshold = Number(meta.fail_rate || __ENV.PERF_FAIL_RATE || 0.01);

  const p99Ok = p99 === null || p99 <= p99Threshold;
  const failOk = failRate === null || failRate < failThreshold;
  const checksOk = checksRate === null || checksRate >= 0.99;
  const overallOk = p99Ok && failOk && checksOk;

  const generated = new Date().toISOString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>k6 perf — ${profile} / ${scenario}</title>
  <style>
    :root { --bg:#0f1419; --card:#1a2332; --text:#e7ecf3; --muted:#8b9cb3; --accent:#3d8bfd;
            --pass:#2ea043; --fail:#f85149; --border:#2d3a4f; }
    * { box-sizing: border-box; }
    body { margin: 0; font: 14px/1.5 system-ui, sans-serif; background: var(--bg); color: var(--text); }
    main { max-width: 720px; margin: 0 auto; padding: 24px 16px 40px; }
    h1 { font-size: 1.25rem; margin: 0 0 4px; }
    .sub { color: var(--muted); margin-bottom: 20px; font-size: 0.9rem; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.75rem;
             font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }
    .badge.pass { background: rgba(46,160,67,.2); color: #3fb950; }
    .badge.fail { background: rgba(248,81,73,.2); color: #ff7b72; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
    .card h2 { margin: 0 0 10px; font-size: 0.8rem; color: var(--muted); text-transform: uppercase;
               letter-spacing: 0.06em; }
    .metric { font-size: 1.35rem; font-weight: 600; color: var(--accent); }
    .metric small { display: block; font-size: 0.75rem; font-weight: 400; color: var(--muted); margin-top: 2px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 0.9rem; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 500; }
    footer { margin-top: 24px; color: var(--muted); font-size: 0.8rem; }
  </style>
</head>
<body>
  <main>
    <h1>${profile} <span style="color:var(--muted)">/</span> ${scenario}</h1>
    <p class="sub">modsecurity-proxy-wasm k6 perf &nbsp;·&nbsp; ${generated} &nbsp;·&nbsp; ${passBadge(overallOk)}</p>
    <div class="grid">
      <div class="card"><h2>Throughput</h2><div class="metric">${fmtNum(rps, 0)}<small>req/s</small></div></div>
      <div class="card"><h2>Requests</h2><div class="metric">${fmtNum(reqs, 0)}<small>total</small></div></div>
      <div class="card"><h2>p99 latency</h2><div class="metric">${fmtMs(p99)}<small>threshold &lt; ${p99Threshold} ms ${passBadge(p99Ok)}</small></div></div>
      <div class="card"><h2>Failed</h2><div class="metric">${fmtPct(failRate)}<small>threshold &lt; ${(failThreshold * 100).toFixed(1)}% ${passBadge(failOk)}</small></div></div>
    </div>
    <table>
      <thead><tr><th>Latency</th><th>Value</th></tr></thead>
      <tbody>
        <tr><td>Average</td><td>${fmtMs(avg)}</td></tr>
        <tr><td>p50</td><td>${fmtMs(p50)}</td></tr>
        <tr><td>p90</td><td>${fmtMs(p90)}</td></tr>
        <tr><td>p95</td><td>${fmtMs(p95)}</td></tr>
        <tr><td>p99</td><td>${fmtMs(p99)}</td></tr>
        <tr><td>Checks passed</td><td>${fmtPct(checksRate)} ${passBadge(checksOk)}</td></tr>
      </tbody>
    </table>
    <footer>
      VUs ${meta.vus || __ENV.PERF_VUS || '?'} · duration ${meta.duration || __ENV.PERF_DURATION || '?'}
      · base ${meta.base_url || __ENV.BASE_URL || '?'}
      ${meta.expected_status ? `· expected HTTP ${meta.expected_status}` : ''}
    </footer>
  </main>
</body>
</html>`;
}

export function htmlCompareReport(left, right, leftLabel, rightLabel) {
  function fromSummary(data) {
    const m = data.metrics || {};
    return {
      p50: metricValue(m, 'http_req_duration', 'med'),
      p90: metricValue(m, 'http_req_duration', 'p(90)'),
      p95: metricValue(m, 'http_req_duration', 'p(95)'),
      rps: metricValue(m, 'http_reqs', 'rate'),
    };
  }

  const l = fromSummary(left);
  const r = fromSummary(right);
  const generated = new Date().toISOString();

  function row(name, lv, rv, unit) {
    let delta = 'n/a';
    if (lv !== null && rv !== null) {
      if (unit === 'rps' && lv > 0) {
        delta = `${(((rv - lv) / lv) * 100).toFixed(1)}%`;
      } else if (unit === 'ms') {
        delta = `${(rv - lv) >= 0 ? '+' : ''}${(rv - lv).toFixed(2)} ms`;
      }
    }
    const fmt = unit === 'rps' ? (v) => fmtNum(v, 0) : fmtMs;
    return `<tr><td>${name}</td><td>${fmt(lv)}</td><td>${fmt(rv)}</td><td>${delta}</td></tr>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>k6 compare — ${leftLabel} vs ${rightLabel}</title>
  <style>
    body { margin: 0; font: 14px/1.5 system-ui, sans-serif; background: #0f1419; color: #e7ecf3; }
    main { max-width: 720px; margin: 0 auto; padding: 24px 16px; }
    h1 { font-size: 1.2rem; }
    .sub { color: #8b9cb3; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid #2d3a4f; }
    th { color: #8b9cb3; }
  </style>
</head>
<body>
  <main>
    <h1>${leftLabel} vs ${rightLabel}</h1>
    <p class="sub">modsecurity-proxy-wasm k6 comparison · ${generated}</p>
    <table>
      <thead><tr><th>Metric</th><th>${leftLabel}</th><th>${rightLabel}</th><th>Delta</th></tr></thead>
      <tbody>
        ${row('p50', l.p50, r.p50, 'ms')}
        ${row('p90', l.p90, r.p90, 'ms')}
        ${row('p95', l.p95, r.p95, 'ms')}
        ${row('RPS', l.rps, r.rps, 'rps')}
      </tbody>
    </table>
  </main>
</body>
</html>`;
}