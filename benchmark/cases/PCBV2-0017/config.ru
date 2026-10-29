# Tiny Rack app: reflects attacker-controlled request params into response headers.
# Two sinks model the two CVEs:
#   ?x=<value>   -> regular response header  X-Reflected: <value>   (CVE-2020-5247 sink)
#   ?eh=<value>  -> early-hints header        Link: <value>          (CVE-2020-5249 residual sink)
# A value containing CR/LF splits the header stream (HTTP response splitting, CWE-113).
require "cgi"

def pcb_parse_query(qs)
  out = {}
  qs.to_s.split("&").each do |pair|
    k, _, v = pair.partition("=")
    next if k.empty?
    out[CGI.unescape(k)] = CGI.unescape(v)
  end
  out
end

app = lambda do |env|
  params = pcb_parse_query(env["QUERY_STRING"])

  # Residual sink: early-hints header (unchecked on V1 = puma 4.3.2)
  eh = params["eh"]
  if eh && !eh.empty? && env["rack.early_hints"]
    env["rack.early_hints"].call("Link" => eh)
  end

  headers = { "Content-Type" => "text/plain" }
  # Original sink: regular response header (rejected on V1 by the CVE-2020-5247 guard)
  x = params["x"]
  headers["X-Reflected"] = x if x && !x.empty?

  [200, headers, ["ok\n"]]
end

run app
