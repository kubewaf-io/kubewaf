import http from 'k6/http';
import { check } from 'k6';
import {
  BASE_URL,
  defaultHeaders,
  defaultOptions,
  writeSummary,
} from '../lib/common.js';

export const options = defaultOptions('benign_get');

export default function () {
  const res = http.get(`${BASE_URL}/`, { headers: defaultHeaders });
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

export function handleSummary(data) {
  return writeSummary(data, { expected_status: 200 });
}