import http from 'k6/http';
import { check } from 'k6';
import {
  BASE_URL,
  defaultHeaders,
  defaultOptions,
  writeSummary,
} from '../lib/common.js';

export const options = defaultOptions('benign_post_1k', {
  http_req_duration: [`p(99)<${Number(__ENV.PERF_P99_MS || 300)}`],
});

const body = JSON.stringify({
  name: 'alice',
  pad: 'x'.repeat(900),
});

export default function () {
  const res = http.post(`${BASE_URL}/api/user`, body, {
    headers: {
      ...defaultHeaders,
      'Content-Type': 'application/json',
    },
  });
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

export function handleSummary(data) {
  return writeSummary(data, { expected_status: 200, body_bytes: body.length });
}