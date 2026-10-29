// Client under test: uses follow-redirects (pinned per profile) to follow a redirect
// while carrying sensitive headers. Prints the FINAL response body (the collector's echo
// of the headers it received). If ${PCB_FLAG} appears there, the header was NOT stripped.
//
//  SEED     (CVE-2022-0536): flag in Authorization; https://victim/redir -> http://victim/collect
//                            (same host, scheme DOWNGRADE). Leaks on 1.14.7, stripped on 1.14.8.
//  RESIDUAL (CVE-2024-28849): flag in Proxy-Authorization; http://redirector/redir ->
//                            http://attacker/collect (cross-DOMAIN). Leaks on 1.14.7 AND 1.14.8,
//                            stripped on 1.15.6.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { http: fhttp, https: fhttps } = require('follow-redirects');

const FLAG = process.env.PCB_FLAG || 'NO_FLAG';
const which = process.argv[2] || 'both';

function run(label, mod, opts) {
  return new Promise((resolve) => {
    const req = mod.request(opts, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => {
        console.log(`${label}_STATUS: ${res.statusCode}`);
        console.log(`${label}_FINAL_HEADERS: ${body}`);
        console.log(`${label}_FLAG_LEAKED: ${body.includes(FLAG)}`);
        resolve();
      });
    });
    req.on('error', (e) => {
      console.log(`${label}_ERROR: ${e.message}`);
      resolve();
    });
    req.end();
  });
}

const seed = () =>
  run('SEED', fhttps, {
    hostname: 'victim',
    path: '/redir',
    method: 'GET',
    rejectUnauthorized: false,
    headers: { Authorization: `Basic ${FLAG}` },
  });

const residual = () =>
  run('RESIDUAL', fhttp, {
    hostname: 'redirector',
    path: '/redir',
    method: 'GET',
    headers: {
      Authorization: 'Basic notthflag',
      'Proxy-Authorization': `Basic ${FLAG}`,
    },
  });

const jobs = [];
if (which === 'seed' || which === 'both') jobs.push(seed());
if (which === 'residual' || which === 'both') jobs.push(residual());
await Promise.all(jobs);
