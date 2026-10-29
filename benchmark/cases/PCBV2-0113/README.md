# freescout-cve-2026-40497

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Incomplete-fix gold case: **CVE-2025-48489 → CVE-2026-40497** (FreeScout stored XSS / CSS injection).

Same sink across the pair: the **mailbox signature**, rendered unescaped in the conversation
view by `Conversation::getSignatureProcessed()`. The guard is `Helper::stripDangerousTags()`, a
tag blocklist that grew across versions but kept leaving gaps.

| profile | FreeScout tag | stripDangerousTags blocklist | role |
|---------|---------------|------------------------------|------|
| v0 | 1.8.179 | `script form iframe` (paired-only regex) | CVE-2025-48489 vulnerable |
| v1 | 1.8.212 | `script form iframe object` | **target** — CVE-2026-40497 vulnerable |
| v2 | 1.8.213 | `… object link meta style` | CVE-2026-40497 fixed |

- **Original seed (CVE-2025-48489):** an *unclosed* `<iframe src=…>` in the signature. Survives
  1.8.179's paired-only regex (executes; CSP disabled per the advisory's documented precondition,
  via the app's own `APP_CSP_ENABLED=false`), stripped by 1.8.180's added unclosed-tag pass on 1.8.212.
- **Residual (CVE-2026-40497):** a `<style>` CSS-exfil block. `style` is absent from 1.8.212's
  blocklist → survives → the CSS `background-image` fires on the real render; 1.8.213 appends
  `style` → stripped.

## Run

```bash
export PCB_FLAG=canary_$(date +%s)
docker compose --profile v0 --profile v1 --profile v2 up -d --build
python3 oracle.py --gate           # -> all four booleans true
docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all
```

Real app, external HTTP trigger, headless-chromium victim. Execution (not reflection) is proven:
the harness never echoes the stored signature, so the per-run flag reaches the internal collector
only when the injected tag both survived `stripDangerousTags()` and executed in the real DOM.
Held-out residual PoC lives in `_heldout/bypass_poc.py`.
