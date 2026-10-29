// Minimal Node HTTP host around @angular/ssr's AngularNodeAppEngine — the same
// shape as a generated Angular SSR `server.ts`. It forwards every request to the
// real engine, which validates headers (the CVE-2026-27738 guard) and, for the
// /old route, emits a redirect whose Location is built by joinUrlParts(
// X-Forwarded-Prefix, '/new') — the exact open-redirect sink.
import '@angular/compiler'; // JIT fallback; must load before Angular injectables
import { createServer } from 'node:http';
import {
  AngularNodeAppEngine,
  writeResponseToNodeResponse,
} from '@angular/ssr/node';
import { ɵsetAngularAppEngineManifest } from '@angular/ssr';

ɵsetAngularAppEngineManifest({
  basePath: '/',
  supportedLocales: { 'en-US': '' }, // single locale -> entry-point key ''
  entryPoints: { '': () => import('./app-server-entry.mjs') },
  allowedHosts: [],
});

const allowedHosts = (process.env.NG_ALLOWED_HOSTS || '127.0.0.1,localhost')
  .split(',')
  .filter(Boolean);
const engine = new AngularNodeAppEngine({ allowedHosts });
const PORT = Number(process.env.PORT || 8080);

const server = createServer(async (req, res) => {
  try {
    const response = await engine.handle(req);
    if (response) {
      await writeResponseToNodeResponse(response, res);
    } else {
      res.statusCode = 404;
      res.end('no angular route');
    }
  } catch (err) {
    res.statusCode = 500;
    res.end('err: ' + (err && err.message));
  }
});
server.listen(PORT, () => console.error('pcb-angular-ssr-host listening on ' + PORT));
