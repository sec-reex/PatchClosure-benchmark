# frozen_string_literal: true
#
# Faithful sink app for the rails-html-sanitizer select+style incomplete-fix pair
# (CVE-2022-32209, fixed 1.4.3 = TARGET  ->  CVE-2022-23520, fixed 1.4.4 = COMPLETE).
#
# A tiny Rack/WEBrick service that runs the REAL Rails::Html::SafeListSanitizer over
# attacker-controlled HTML and serves the *sanitized* output verbatim inside a page
# (exactly the way a Rails app that "sanitizes then displays user HTML" would). The
# rails-html-sanitizer gem VERSION installed in the image is the only thing that changes
# across v0/v1/v2 (build-arg RHS_VER); loofah/nokogiri are pinned identical. Same call,
# same allowlist (which deliberately permits BOTH `select` and `style`), three consecutive
# releases -> the browser-side execution outcome differs per version.
#
# The two request modes reproduce the exact API distinction the advisories turn on:
#   /?mode=tags&html=...   -> sanitize(html, tags: OVERRIDE)          (PER-CALL :tags option)
#   /?mode=class&html=...  -> sanitize(html)  with SafeListSanitizer.allowed_tags = OVERRIDE
#                                                                     (CLASS-LEVEL override)
# CVE-2022-32209's 1.4.3 fix (remove_safelist_tag_combinations) is ONLY reached on the
# per-call `options[:tags]` branch; the class-level `allowed_tags` fallback is NOT run
# through it -> that is the incomplete-fix gap that CVE-2022-23520 (1.4.4) later closes at
# the root (escaping everything the HTML4 parser treats as CDATA).

require "sinatra/base"
require "rails-html-sanitizer"

# A plausible "allow rich markup" allowlist that OVERRIDES the default to permit BOTH
# `select` and `style` (the dangerous combination the advisories are about), plus the
# foreign-content wrappers and some benign formatting tags. NOTE: `img`/`script` are NOT
# needed in the allowlist -- the mutation promotes them out of the <style> CDATA context.
OVERRIDE_TAGS = %w[
  select style svg math
  p br b i u em strong span div a ul ol li h1 h2 h3
  mi mo mn ms mtext annotation-xml
].freeze
OVERRIDE_ATTRS = %w[href src alt title class id style].freeze

# Class-level override (the config.action_view.sanitized_allowed_tags / allowed_tags= path).
Rails::Html::SafeListSanitizer.allowed_tags = OVERRIDE_TAGS
Rails::Html::SafeListSanitizer.allowed_attributes = OVERRIDE_ATTRS

RHS_VER = begin
  Gem.loaded_specs["rails-html-sanitizer"].version.to_s
rescue StandardError
  "unknown"
end
LOOFAH_VER = begin
  Gem.loaded_specs["loofah"].version.to_s
rescue StandardError
  "unknown"
end

class SinkApp < Sinatra::Base
  set :server, "webrick"
  set :bind, "0.0.0.0"
  set :port, (ENV["PORT"] || "80").to_i
  set :environment, :production
  disable :protection
  disable :logging

  def sanitize_html(raw, mode)
    s = Rails::Html::SafeListSanitizer.new
    if mode == "tags"
      # PER-CALL :tags option -> reaches remove_safelist_tag_combinations on 1.4.3, which mutates
      # the array in place (tags.delete("style")), so pass a fresh mutable dup (as a real caller would).
      s.sanitize(raw, tags: OVERRIDE_TAGS.dup, attributes: OVERRIDE_ATTRS.dup)
    else
      # CLASS-LEVEL allowed_tags fallback -> does NOT go through the 1.4.3 combination scrub.
      s.sanitize(raw)
    end
  end

  # THE SINK -- real Rails::Html::SafeListSanitizer, output served verbatim in a page.
  get "/" do
    raw = params["html"] || ""
    mode = params["mode"] || "class"
    sanitized = sanitize_html(raw, mode)
    content_type "text/html"
    "<!doctype html><html><head><meta charset='utf-8'><title>rhs-sink</title></head>" \
      "<body><div id='content'>#{sanitized}</div></body></html>"
  end

  # Return ONLY the sanitized string (no page wrapper) -- host oracle records exact
  # server-side sanitizer output per version for the repro log (server-side proof).
  get "/raw" do
    raw = params["html"] || ""
    mode = params["mode"] || "class"
    content_type "text/plain"
    sanitize_html(raw, mode)
  end

  get "/health" do
    content_type "text/plain"
    "ok rhs=#{RHS_VER} loofah=#{LOOFAH_VER}"
  end
end

SinkApp.run!
