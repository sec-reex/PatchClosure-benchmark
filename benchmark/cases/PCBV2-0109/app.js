'use strict'

// Real Fastify server using the real @fastify/static package.
// allowedPath enforces a security boundary over /private/ (returns 404 for any
// pathname starting with /private/). The vulnerability class:
//  - CVE-2026-15074: non-leading '..' segments bypass the boundary (fixed 10.1.1)
//  - CVE-2026-7120:  non-canonical '/./' (and '//') pathnames bypass the
//    boundary because allowedPath runs before path normalization (fixed 10.1.2)

const fastify = require('fastify')({ logger: false })

fastify.register(require('@fastify/static'), {
  root: '/data/root',
  prefix: '/static/',
  allowedPath: (pathname) => !pathname.startsWith('/private/')
})

fastify.listen({ port: 3000, host: '0.0.0.0' }, (err) => {
  if (err) throw err
})
