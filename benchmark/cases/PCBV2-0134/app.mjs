// Minimal REAL Koa app exercising the genuine ctx.response.back() redirect guard.
// The redirect decision is made ENTIRELY by the real koa library bytes
// (lib/response.js :: back()). This app plants nothing; it only exposes the sink.
import Koa from 'koa'

const app = new Koa()

app.use(async (ctx) => {
  if (ctx.path === '/redirect') {
    // ctx.get('Referrer') inside koa reads the client-supplied Referer header.
    // The real koa back() applies its own open-redirect guard and calls
    // this.redirect(...), setting the Location header. `/` is the safe fallback.
    ctx.response.back('/')
    return
  }
  ctx.status = 200
  ctx.type = 'text/plain'
  ctx.body = 'koa-pcb ok\n'
})

const port = Number(process.env.PORT || 3000)
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`koa-pcb listening on ${port} (koa ${process.env.KOA_VERSION || '?'})`)
})
