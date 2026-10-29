'use strict'
// PatchClosure-Bench SUT: fast-jwt JWT algorithm confusion (CWE-347).
// CVE-2023-48223 (V1 target, incomplete fix) -> CVE-2026-34950 (V2 complete fix).
//
// The app pins fast-jwt per profile (build-arg) and verifies admin tokens with the
// server's RSA PUBLIC key, WITHOUT restricting `algorithms` (the classic algorithm-
// confusion precondition: allowed algs are DERIVED from the key via
// detectPublicKeyAlgorithms in src/crypto.js). If the public key string is
// misclassified as an HMAC secret, HS256 tokens signed with the (public) key verify.
//
// Two realistic deployments are exposed as two routes over the SAME sink (crypto.js
// key classification) and the SAME flag channel:
//   /admin          -> key = PUB              (PKCS1 "BEGIN RSA PUBLIC KEY", no leading ws)
//   /admin-tainted  -> key = "\n" + PUB       (leading newline, per GHSA-mvf2-f6gm-w987 PoC:
//                                              a database-retrieved key with a leading newline)
const crypto = require('crypto')
const express = require('express')
const { createVerifier } = require('fast-jwt')

const FLAG = process.env.PCB_FLAG || 'PCBFLAG_missing'
const FJVER = require('fast-jwt/package.json').version

// RSA keypair; PUBLIC key emitted in PKCS1 ("-----BEGIN RSA PUBLIC KEY-----").
// PKCS1 is what defeats V0's `.includes('-----BEGIN PUBLIC KEY-----')` check (CVE-2023-48223).
const { publicKey: PUB } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
})

function buildVerifier(keyStr, label) {
  // Eager build => classification (detectPublicKeyAlgorithms) happens now, per route.
  try {
    const v = createVerifier({ key: keyStr })
    console.log(`[verifier ${label}] built ok on fast-jwt ${FJVER}`)
    return v
  } catch (e) {
    console.log(`[verifier ${label}] build FAILED: ${e && e.message}`)
    return () => { throw new Error('verifier-build-failed: ' + (e && e.message)) }
  }
}

const verifierClean = buildVerifier(PUB, 'clean')
const verifierTainted = buildVerifier('\n' + PUB, 'tainted')

function adminHandler(verifier, routeLabel) {
  return (req, res) => {
    const auth = req.headers['authorization'] || ''
    const m = /^Bearer\s+(.+)$/.exec(auth)
    if (!m) return res.status(401).json({ error: 'missing bearer token' })
    let payload
    try {
      payload = verifier(m[1])
    } catch (e) {
      return res.status(401).json({ error: 'verify_failed', route: routeLabel, detail: String((e && e.message) || e) })
    }
    if (payload && payload.role === 'admin') {
      return res.json({ ok: true, route: routeLabel, flag: FLAG, payload })
    }
    return res.status(403).json({ error: 'not_admin', route: routeLabel, payload })
  }
}

const app = express()
app.get('/health', (_req, res) => res.json({ ok: true, fastjwt: FJVER }))
app.get('/fjver', (_req, res) => res.type('text/plain').send(FJVER))
app.get('/pubkey', (_req, res) => res.type('text/plain').send(PUB)) // public key is public knowledge
app.get('/admin', adminHandler(verifierClean, 'clean'))
app.get('/admin-tainted', adminHandler(verifierTainted, 'tainted'))

app.listen(3000, () => {
  console.log(`[fast-jwt SUT] listening on 3000; fast-jwt=${FJVER}`)
  console.log(`[fast-jwt SUT] PUB header: ${PUB.split('\n')[0]}`)
})
