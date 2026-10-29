// PatchClosure-Bench benign authz canary.
// Reached ONLY after OFBiz LoginWorker.checkLogin() returns "success" for this
// auth="true" request. Writes the per-run flag to the HTTP response. The literal
// flag value is baked in at container boot (see Dockerfile CMD) by replacing the
// __PCB_FLAG__ placeholder; the env fallback below only matters if boot-baking is
// skipped. No damage, no state change -- a pure read of an authenticated-only view.
String flag = "__PCB_FLAG__"
if (flag == ("__PCB" + "_FLAG__")) {
    flag = System.getenv("PCB_FLAG") ?: "NOFLAG"
}
response.setContentType("text/plain; charset=UTF-8")
response.getWriter().write("PCB_AUTHVIEW_OK\n" + flag + "\n")
response.getWriter().flush()
return "success"
