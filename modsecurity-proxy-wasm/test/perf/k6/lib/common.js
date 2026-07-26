import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.4/index.js';
import { htmlReport } from './html-report.js';

export const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:18080';
export const HOST_HEADER = __ENV.HOST_HEADER || 'www.example.com';
export const PERF_VUS = Number(__ENV.PERF_VUS || 32);
export const PERF_DURATION = __ENV.PERF_DURATION || '60s';
export const PERF_WARMUP = __ENV.PERF_WARMUP || '15s';
export const PERF_P99_MS = Number(__ENV.PERF_P99_MS || 200);
export const PERF_FAIL_RATE = Number(__ENV.PERF_FAIL_RATE || 0.01);

export const defaultHeaders = {
  Host: HOST_HEADER,
  Accept: 'text/html',
  'User-Agent': 'k6-modsecurity-proxy-wasm-perf',
};

export function defaultOptions(scenarioName, extraThresholds = {}) {
  return {
    scenarios: {
      [scenarioName]: {
        executor: 'constant-vus',
        vus: PERF_VUS,
        duration: PERF_DURATION,
      },
    },
    thresholds: {
      http_req_failed: [`rate<${PERF_FAIL_RATE}`],
      checks: ['rate>0.99'],
      http_req_duration: [`p(99)<${PERF_P99_MS}`],
      ...extraThresholds,
    },
  };
}

export function writeSummary(data, meta = {}) {
  const profile = __ENV.PERF_PROFILE || 'unknown';
  const scenario = __ENV.PERF_SCENARIO || 'unknown';
  const out = {
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };

  if (__ENV.PERF_SKIP_FILE_EXPORT === '1') {
    return out;
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const runMeta = {
    profile,
    scenario,
    base_url: BASE_URL,
    vus: PERF_VUS,
    duration: PERF_DURATION,
    p99_threshold_ms: PERF_P99_MS,
    fail_rate: PERF_FAIL_RATE,
    ...meta,
  };
  const detailPath = `/results/k6-${profile}-${scenario}-${stamp}.json`;
  out[detailPath] = JSON.stringify(
    {
      meta: runMeta,
      metrics: data.metrics,
      root_group: data.root_group,
    },
    null,
    2,
  );
  out['/results/k6-report.html'] = htmlReport(data, runMeta);

  return out;
}