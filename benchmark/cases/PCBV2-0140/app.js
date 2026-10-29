'use strict'

// Real Fastify "template compiler service" using the real lodash package.
// POST /compile {source, variable, importsKeys} -> String(_.template(...)()).
// The service accepts untrusted `variable` and `imports` key NAMES (a common
// "named imports" app pattern) - the exact usage CVE-2021-23337 / CVE-2026-4800
// describe. Canary /canary.txt planted by entrypoint.
//
// NOTE: imports keys are bound to undefined (the app has no values for
// user-supplied import names); this triggers the default-parameter injection.

const fastify = require('fastify')({ logger: false })
const _ = require('lodash')

fastify.post('/compile', async (req, reply) => {
  const { source, variable, importsKeys } = req.body || {}
  if (typeof source !== 'string') {
    return reply.code(400).send({ error: 'source required' })
  }
  const options = {}
  if (typeof variable === 'string') options.variable = variable
  if (Array.isArray(importsKeys)) {
    const imports = {}
    for (const k of importsKeys) imports[k] = undefined
    options.imports = imports
  }
  try {
    const compiled = _.template(source, options)
    const out = compiled()
    return reply.send(String(out))
  } catch (e) {
    return reply.code(400).send({ error: String(e.message || e) })
  }
})

fastify.listen({ port: 3000, host: '0.0.0.0' }, (err) => {
  if (err) throw err
})
