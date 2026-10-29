# deser_yii2_behavior_typecheck

Incomplete-fix pair (CWE-502 / CWE-470, PHP object injection) in **Yii 2** (`yiisoft/yii2`).
**CISA KEV — exploited in the wild Feb–Apr 2025.**

| role | version | fix | behavior of the `as <name>` object-injection sink |
|------|---------|-----|-----------------------------------------------------|
| V0 vulnerable | 2.0.49 | pre-CVE-2024-4990 | `__set` passes the attacker array straight to `Yii::createObject` → any class instantiated |
| V1 target (incomplete) | 2.0.50 | **CVE-2024-4990** | adds a behavior type check `is_subclass_of($value['class'], Behavior::class)` — blocks the DIRECT `class` payload, **but the check reads `class` while `createObject` instantiates via `__class` first** |
| V2 fixed | 2.0.52 | **CVE-2024-58136** | checks `__class` **first** (matching `createObject`'s precedence) → both forms refused |

## How it is triggered (real web app, external HTTP)
A REAL, unmodified Yii2 web app (`yii\web\Application` on the PHP built-in server). An external
**`POST /trigger`** carries a JSON body that `app\controllers\TriggerController::actionIndex`
mass-assigns onto a plain `yii\base\Component` (`foreach ($body as $k=>$v) { $c->$k = $v; }`) — the
framework's own config-apply pattern — reaching `Component::__set('as <name>')`. If `app\PcbFlagProbe`
is instantiated, its constructor reads `/canary/flag.txt` and the token is echoed into the HTTP
**response body**. No `docker exec`, no in-process call.

## The two payloads (same sink: `Component::__set('as <name>', <array>)`)
- **Original (CVE-2024-4990)** — `{"as pcb": {"class": "app\\PcbFlagProbe"}}` — instantiates on V0, blocked on V1/V2.
- **Residual (CVE-2024-58136)** — `{"as pcb": {"class": "app\\PcbLegitBehavior", "__class": "app\\PcbFlagProbe"}}` —
  `class` names a legit Behavior to pass V1's type check, `__class` steers `createObject` to instantiate
  the attacker class → **instantiates on V1**, blocked on V2.

## Benign canary (safeguard-safe)
No POP gadget chain / no command exec. `app\PcbFlagProbe` is our OWN benign class whose constructor
reads the planted `${PCB_FLAG}` canary (`/canary/flag.txt`) and echoes it. Instantiating it via the
sink == the type-allowlist was bypassed → flag surfaces.

## Run the gate
```
python3 oracle.py --run-gate --with-v2
```
Variant A: `original@v0 reaches`, `original@v1 blocked`, `residual@v1 reaches` (+ both blocked@v2).

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。
