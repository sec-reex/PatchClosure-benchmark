# frozen_string_literal: true
#
# Faithful sink app for the Loofah SVG-animate-republish incomplete-fix pair
# (CVE-2018-16468, fixed loofah 2.2.3 = TARGET  ->  CVE-2019-15587, fixed loofah 2.3.1 = COMPLETE).
#
# A tiny Rack/WEBrick service that runs the REAL Loofah sanitizer over attacker-controlled
# HTML/SVG and REPUBLISHES it: sanitize once, then re-parse + re-serialize the sanitized output
# (exactly the "crafted SVG element is republished" scenario both CVEs describe -- a stored,
# sanitized fragment that is later re-emitted). The Loofah gem VERSION installed in the image is
# the only thing that changes across v0/v1/v2 (build-arg LOOFAH_VER); nokogiri/crass are pinned
# identical. Same call, same SVG-attribute allowlist, three consecutive releases -> the browser-
# side execution outcome differs per version because the allowlist for the SVG <animate> value
# attributes (from/to/by/values) is narrowed release by release.
#
#   V0 = 2.2.2 : from,to,by,values ALL allowed  -> the animate value smuggles a javascript: URI
#   V1 = 2.2.3 : `from` removed (CVE-2018-16468) -> `from`-vector blocked; to/by/values STILL
#                allowed -> the `values`-vector survives  (INCOMPLETE FIX)
#   V2 = 2.3.1 : to/by/values removed (CVE-2019-15587) -> every animate value vector blocked

require "sinatra/base"
require "loofah"

LOOFAH_VER = begin
  Gem.loaded_specs["loofah"].version.to_s
rescue StandardError
  "unknown"
end
NOKOGIRI_VER = begin
  Gem.loaded_specs["nokogiri"].version.to_s
rescue StandardError
  "unknown"
end

# THE REPUBLISH SINK -- real Loofah. Sanitize the untrusted fragment, then re-parse the sanitized
# output and re-serialize it (the "republish": a stored sanitized fragment re-emitted into a page).
# Loofah keeps any SVG animate value attribute that is still in the allowlist, so a smuggled
# javascript: URI rides through both passes intact whenever its attribute survives the allowlist.
def republish(raw)
  once = Loofah.fragment(raw).scrub!(:strip).to_s
  Loofah.fragment(once).scrub!(:strip).to_s
end

class SinkApp < Sinatra::Base
  set :server, "webrick"
  set :bind, "0.0.0.0"
  set :port, (ENV["PORT"] || "80").to_i
  set :environment, :production
  disable :protection
  disable :logging

  # THE SINK -- real Loofah republish, output served verbatim in a page.
  get "/" do
    raw = params["html"] || ""
    content_type "text/html"
    "<!doctype html><html><head><meta charset='utf-8'><title>loofah-sink</title></head>" \
      "<body><div id='content'>#{republish(raw)}</div></body></html>"
  end

  # Return ONLY the republished sanitized string (no page wrapper) -- host oracle records the
  # exact server-side Loofah output per version for the repro log (server-side proof).
  get "/raw" do
    raw = params["html"] || ""
    content_type "text/plain"
    republish(raw)
  end

  get "/health" do
    content_type "text/plain"
    "ok loofah=#{LOOFAH_VER} nokogiri=#{NOKOGIRI_VER}"
  end
end

SinkApp.run!
