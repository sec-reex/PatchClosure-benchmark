# Compiled frontend assets (froxlor 2.3.5 / v1 profile)

Upstream froxlor git tags do not ship `templates/Froxlor/build/`. Without a
vite manifest the panel's `vite()` helper falls back to linking the entry source
(`templates/Froxlor/assets/scss/app.scss`) and throws

    Exception: Unknown file extension for file templates/Froxlor/assets/scss/app.scss

which kills every dynamic panel page (login included) with a Twig fatal — the
case then answers 200/302 on static routes but is unusable.

`froxlor-build/` is the hashed output of the pinned tag's own build:

    npm ci                      # registry.npmmirror.com
    npm run build               # vite 6 + laravel-vite-plugin
    # output: templates/Froxlor/build/{manifest.json,assets/*}

It is copied into `/var/www/html/templates/Froxlor/build/` by the Dockerfile.
Only the v1 profile (2.3.5) is scored; the v0/v2 profiles use the same manifest
keys, so the panel renders there as well (v0 2.0.11 uses laravel-mix and does
not read this directory).

The panel cron (`bin/froxlor-cli froxlor:cron`) is what executes the ExportCron
job queued by `DataDump.add` and what regenerates the BIND zones, so the
entrypoint also runs it in a short background loop (a real froxlor host runs it
continuously; the benchmark scores from outside the container).
