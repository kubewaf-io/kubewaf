import http from 'k6/http';
import { check } from 'k6';
import {
  BASE_URL,
  defaultHeaders,
  defaultOptions,
  writeSummary,
} from '../lib/common.js';

export const options = defaultOptions('block_xss', {
  http_req_duration: [`p(99)<${Number(__ENV.PERF_P99_MS || 400)}`],
});

const payload = encodeURIComponent('<script>alert(1)</script>');

export default function () {
  const res = http.get(`${BASE_URL}/?q=${payload}`, { headers: defaultHeaders });
  check(res, {
    'status is 403': (r) => r.status === 403,
  });
}

export function handleSummary(data) {
  return writeSummary(data, { expected_status: 403 });
}