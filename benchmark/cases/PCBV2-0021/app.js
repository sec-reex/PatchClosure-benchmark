'use strict'

// Real Fastify server using the real @fastify/static package.
// Guard route blocks direct access to /static/secret/*. The vulnerability class:
//  - CVE-2026-6414: encoded %2F separators bypass the guard route.
//  - CVE-2026-15074: non-leading '..' segments survive find-my-way matching and
//    are normalized by @fastify/send before its own traversal guard.

const fastify = require('fastify')({ logger: false })

// Guard route: blocks direct access to anything under /static/secret/
fastify.get('/static/secret/*', (req, reply) => reply.code(403).send('blocked'))
fastify.get('/static/secret', (req, reply) => reply.code(403).send('blocked'))

fastify.register(require('@fastify/static'), {
  root: '/data/root',
  prefix: '/static/'
})

fastify.listen({ port: 3000, host: '0.0.0.0' }, (err) => {
  if (err) throw err
})
