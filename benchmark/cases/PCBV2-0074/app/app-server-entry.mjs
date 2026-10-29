// Hand-written equivalent of the server entry that `ng build` generates for an
// Angular SSR app. It registers an app manifest whose serialized route tree
// contains ONE benign server-side redirect (/old -> /new, HTTP 302) and re-exports
// the SSR engine factory that AngularAppEngine looks up per entry point.
//
// This is ordinary application wiring: it exercises the REAL, unmodified
// @angular/ssr request pipeline (validateRequest -> AngularServerApp.handle ->
// joinUrlParts(X-Forwarded-Prefix, ...) at the redirect sink). No secret/canary
// is embedded here — the per-run flag is supplied by the environment/PoC.
import '@angular/compiler'; // JIT fallback (partial-compiled Angular libs)
import { ɵsetAngularAppManifest, ɵgetOrCreateAngularServerApp } from '@angular/ssr';

ɵsetAngularAppManifest({
  inlineCriticalCss: false,
  baseHref: '/',
  locale: undefined,
  assets: {}, // never touched on the pure-redirect path
  routes: [
    { route: '/old', redirectTo: '/new', status: 302 },
  ],
  entryPointToBrowserMapping: {},
});

export { ɵgetOrCreateAngularServerApp };
