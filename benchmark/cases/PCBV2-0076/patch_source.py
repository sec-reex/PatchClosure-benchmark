#!/usr/bin/env python3
"""Build-time patcher for Apache httpd 2.2.21 (mod_proxy reverse-proxy SSRF guard).

The CVE-2011-3368 fix that shipped in httpd 2.2.22 (backport r1235443 of trunk
r1209432 + r1233604) adds the SAME request-URI guard to TWO independent
translate hooks, which guard TWO reverse-proxy front-ends onto the same
mod_proxy routing sink:

  * modules/mappers/mod_rewrite.c :: hook_uri2file   -> guards `RewriteRule ... [P]`
  * modules/proxy/mod_proxy.c     :: proxy_trans      -> guards `ProxyPass / ProxyPassMatch`

The guard DECLINEs any request whose URI does not begin with '/', so an
`@authority` request-target (which turns the intended backend into userinfo and
routes to an arbitrary internal host) is no longer expanded into a proxy target.

Patch levels (differ ONLY in these two files):
  v0 : neither hook guarded                  -> CVE-2011-3368 vulnerable
  v1 : mod_rewrite.c guarded ONLY            -> the RewriteRule [P] vector (the canonical
       (mod_proxy.c still open)                 CVE-2011-3368 PoC) is fixed, but the sibling
                                                ProxyPassMatch front-end still reaches the same
                                                SSRF sink => INCOMPLETE FIX (CVE-2011-3639 /
                                                CVE-2011-4317 "additional cases").   <- TARGET
  v2 : BOTH hooks guarded                     -> both front-ends closed (== 2.2.22)

Verbatim upstream code (Apache-2.0); only the insertion point is scripted so it
applies robustly regardless of 2.2.21 line numbers.
"""
import sys

SRC = "/usr/local/src/httpd-2.2.21"
MOD_PROXY = f"{SRC}/modules/proxy/mod_proxy.c"
MOD_REWRITE = f"{SRC}/modules/mappers/mod_rewrite.c"

CHECK = (
    "    if ((r->unparsed_uri[0] == '*' && r->unparsed_uri[1] == '\\0')\n"
    "        || !r->uri || r->uri[0] != '/') {\n"
    "        return DECLINED;\n"
    "    }\n"
)

# --- mod_proxy.c :: proxy_trans (insert after the r->proxyreq early-return) ---
PROXY_ANCHOR = (
    "         * in proxy_detect\n"
    "         */\n"
    "        return OK;\n"
    "    }\n"
    "\n"
    "    /* XXX: since r->uri has been manipulated already"
)
PROXY_NEW = (
    "         * in proxy_detect\n"
    "         */\n"
    "        return OK;\n"
    "    }\n"
    "\n"
    + CHECK +
    "\n"
    "    /* XXX: since r->uri has been manipulated already"
)

# --- mod_rewrite.c :: hook_uri2file (insert before the SCRIPT_URL env setup) ---
REWRITE_ANCHOR = (
    "    if (conf->server != r->server) {\n"
    "        return DECLINED;\n"
    "    }\n"
    "\n"
    "    /*\n"
    "     *  add the SCRIPT_URL variable to the env."
)
REWRITE_NEW = (
    "    if (conf->server != r->server) {\n"
    "        return DECLINED;\n"
    "    }\n"
    "\n"
    + CHECK +
    "\n"
    "    /*\n"
    "     *  add the SCRIPT_URL variable to the env."
)


def _patch(path, anchor, new):
    s = open(path).read()
    assert anchor in s, f"anchor not found in {path}"
    open(path, "w").write(s.replace(anchor, new, 1))


def main(level):
    if level == "v0":
        print("[patch] v0: pristine 2.2.21 (neither hook guarded)")
        return
    # v1 and v2 both guard mod_rewrite (the RewriteRule [P] front-end).
    _patch(MOD_REWRITE, REWRITE_ANCHOR, REWRITE_NEW)
    msg = "[patch] mod_rewrite.c hook_uri2file guarded"
    if level == "v2":
        _patch(MOD_PROXY, PROXY_ANCHOR, PROXY_NEW)
        msg += " + mod_proxy.c proxy_trans guarded"
    print(f"[patch] {level}: {msg}")


if __name__ == "__main__":
    main(sys.argv[1])
