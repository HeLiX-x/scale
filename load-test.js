// load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';

// --- Configuration ---
const BASE_URL = 'https://scale-server-7nr9.onrender.com';
const JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjAyMDcwMDksInN1YiI6IjEifQ.PnBbeG5pevw6-4EagSkqdfAOKQECaduPvM36Enxc-Bs";
const PEER_PUBLIC_KEY = "zaHIjQqYOEpINATCW7XWjiN6ECVvc80Zu2mXCjMS8XA="; // Your laptop's public key

export const options = {
  stages: [
    { duration: '30s', target: 20 }, // Use a lower target for the free tier
    { duration: '1m', target: 20 },
    { duration: '10s', target: 0 },
  ],
  // Add a longer timeout to handle initial spin-up
  thresholds: {
    'http_req_duration': ['p(95)<1500'], // 95% of requests should be under 1.5s
  },
};

export default function () {
  const peerParams = {
    headers: {
      'Authorization': `Bearer ${JWT_TOKEN}`,
    },
    // Set a timeout for individual requests
    timeout: '30s',
  };

  const peerRes = http.get(`${BASE_URL}/api/devices/${PEER_PUBLIC_KEY}/peers`, peerParams);

  // Correctly check if the request was successful before checking the body
  check(peerRes, {
    'get peers status was 200': (r) => r.status === 200,
    'response body contains peer_configs': (r) => {
      if (r.body) {
        return r.body.includes('peer_configs');
      }
      return false; // If body is null, the check fails safely
    },
  });

  sleep(1);
}