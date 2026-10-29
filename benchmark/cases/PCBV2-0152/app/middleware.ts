import { NextRequest, NextResponse } from "next/server";

// Auth gate: only requests carrying the session cookie `auth=1` may reach /admin.
// Everything else is rejected with 401 BEFORE the protected page renders.
//
// The `matcher` restricts middleware to the human-facing /admin route. The whole
// point of CVE-2026-44575 / CVE-2026-45109 is that App Router also serves the SAME
// page at transport-variant paths (e.g. /admin.rsc, /admin.segments/...segment.rsc)
// which a matcher generated for `/admin` does not cover on affected builds -> the
// middleware never runs for those variants and the protected page leaks.
export function middleware(req: NextRequest) {
  const authed = req.cookies.get("auth")?.value === "1";
  if (!authed) {
    return new NextResponse("unauthorized: middleware auth gate blocked this request", {
      status: 401,
      headers: { "content-type": "text/plain", "x-mw": "blocked" },
    });
  }
  const res = NextResponse.next();
  res.headers.set("x-mw", "allowed");
  return res;
}

export const config = {
  matcher: ["/admin"],
};
