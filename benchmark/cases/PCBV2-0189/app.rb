# frozen_string_literal: true
#
# Faithful sink app for the Sanitize foreign-content -> noscript incomplete-fix pair
# (CVE-2020-4054, fixed sanitize 5.2.1 = TARGET  ->  CVE-2023-23627, fixed sanitize 6.0.1 = COMPLETE).
#
# A tiny Rack/WEBrick service that runs the REAL Sanitize sanitizer over attacker-controlled
# HTML and serves the sanitized output verbatim in a page (exactly the way an application that
# "sanitizes then displays user HTML" would). The Sanitize gem VERSION installed in the image is
# the only thing that changes across v0/v1/v2 (build-arg SANITIZE_VER); nokogiri/nokogumbo/crass
# are pinned identical across v0/v1. Same call, same config, three releases -> the browser-side
# execution outcome differs per version because the two fixes narrow foreign-content then noscript
# handling.
#
# The config is Sanitize's RELAXED config PLUS `noscript` in the element allowlist -- a plausible
# "allow rich markup incl. <noscript> fallbacks" policy. RELAXED already allows `style`, `img`,
# `title` but NOT `math`/`svg`/`noscript`:
#   - the ORIGINAL (CVE-2020-4054) smuggles live markup through a non-allowlisted <math>/<svg>
#     foreign-content wrapper whose contents 5.2.0 failed to strip;
#   - the RESIDUAL (CVE-2023-23627) smuggles live markup through an allowlisted <noscript> whose
#     contents Nokogiri parses with SCRIPTING DISABLED while the browser parses with scripting
#     enabled (the desync). This custom-allowlist noscript path is exactly what GHSA-fw3g-2h3j-qmm7
#     says the 5.2.1 fix left open.

require "sinatra/base"
require "sanitize"

SANITIZE_VER = begin
  Sanitize::VERSION
rescue StandardError
  "unknown"
end
NOKOGIRI_VER = begin
  require "nokogiri"
  Nokogiri::VERSION
rescue StandardError
  "unknown"
end

# RELAXED + noscript. This is the vulnerable custom allowlist both advisories describe: RELAXED for
# the foreign-content bypass (GHSA-p4x4-rw2p-8j8m lists it), plus `noscript` explicitly allowlisted
# for the scripting-desync bypass (GHSA-fw3g-2h3j-qmm7: "only affects users using a custom config
# that adds `noscript` to the element allowlist").
CONFIG = Sanitize::Config.merge(
  Sanitize::Config::RELAXED,
  :elements => Sanitize::Config::RELAXED[:elements] + %w[noscript]
)

def scrub(raw)
  Sanitize.fragment(raw, CONFIG)
end

class SinkApp < Sinatra::Base
  set :server, "webrick"
  set :bind, "0.0.0.0"
  set :port, (ENV["PORT"] || "80").to_i
  set :environment, :production
  disable :protection
  disable :logging

  # THE SINK -- real Sanitize, output served verbatim in a page.
  get "/" do
    raw = params["html"] || ""
    content_type "text/html"
    "<!doctype html><html><head><meta charset='utf-8'><title>sanitize-sink</title></head>" \
      "<body><div id='content'>#{scrub(raw)}</div></body></html>"
  end

  # Return ONLY the sanitized string (no page wrapper) -- host oracle records the exact server-side
  # Sanitize output per version for the repro log (server-side proof).
  get "/raw" do
    raw = params["html"] || ""
    content_type "text/plain"
    scrub(raw)
  end

  get "/health" do
    content_type "text/plain"
    "ok sanitize=#{SANITIZE_VER} nokogiri=#{NOKOGIRI_VER}"
  end
end

SinkApp.run!
