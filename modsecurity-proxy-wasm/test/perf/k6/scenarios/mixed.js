import http from 'k6/http';
import { check } from 'k6';
import {
  BASE_URL,
  defaultHeaders,
  defaultOptions,
  writeSummary,
} from '../lib/common.js';

export const options = defaultOptions('mixed_95_5', {
  http_req_duration: [`p(99)<${Number(__ENV.PERF_P99_MS || 300)}`],
});

const attackPayload = encodeURIComponent('<script>alert(1)</script>');

export default function () {
  const attack = Math.random() < 0.05;
  const res = attack
    ? http.get(`${BASE_URL}/?q=${attackPayload}`, { headers: defaultHeaders })
    : http.get(`${BASE_URL}/`, { headers: defaultHeaders });

  check(res, {
    'expected status': (r) => (attack ? r.status === 403 : r.status === 200),
  });
}

export function handleSummary(data) {
  return writeSummary(data, { mix: '95% allow / 5% block' });
}