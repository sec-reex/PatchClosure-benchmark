#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Faithful-core harness for the Faraday build_exclusive_url host-scoping guard
# (CVE-2026-25765 / GHSA-33mh-2634-fwr2  ->  CVE-2026-33637 / GHSA-5rv5-xj5j-3484).
#
# Faraday (rubygems `faraday`, the de-facto Ruby HTTP client abstraction) is routinely used to build a
# "destination-pinned" outbound client: the app constructs ONE Faraday::Connection with a FIXED base URL
# (the single upstream it is allowed to call -- an internal microservice, a webhook relay, a link-preview
# fetcher) carrying connection-scoped Authorization headers, then lets a user supply only the request
# target. The security expectation is that the user-supplied target may pick a resource ON that base host
# but can NEVER redirect the request to a different host. Faraday resolves the user target against the base
# in `Faraday::Connection#build_exclusive_url` (lib/faraday/connection.rb). Both CVEs are host-scoping
# bypasses at exactly this sink. Standing up a full app just to drive ONE pinned outbound fetch is
# disproportionate, so this image runs the REAL, per-version faraday gem as the client in front of the
# net_http sink. No offensive PoC is used; the target is a benign per-run ${PCB_FLAG} served by an
# internal-only sidecar with no published host port.
#
# Three roles (ROLE env), one image per faraday version:
#   ROLE=base      trusted-base.pcb -- the PUBLIC/trusted upstream the server is CONFIGURED (base URL) to
#                  call. Serves a benign non-flag body on any path -- where a correctly host-scoped
#                  request MUST land.
#   ROLE=attacker  attacker.pcb -- INTERNAL-only canary. Serves ${PCB_FLAG} on any path. NO published host
#                  port and a different hostname than the base, so the flag can appear in a server response
#                  ONLY if the user target overrode the fixed base host to reach `attacker.pcb`.
#   ROLE=server    the destination-pinned proxy. GET /fetch?to=<target>&mode=<string|uri> builds
#                  `conn.get(target)` where conn = Faraday.new(url: 'http://trusted-base.pcb') and echoes
#                  the fetched upstream body. The app code is byte-identical across profiles; only the
#                  faraday VERSION differs:
#
#   FARADAY v0  faraday 2.14.0 -- pre CVE-2026-25765. build_exclusive_url leaves a protocol-relative
#               target untouched for BOTH String and URI inputs: `//attacker.pcb/flag` starts with '/'
#               so the `./`-prefix guard does not fire -> URI#merge takes the '//authority' -> host
#               OVERRIDDEN -> reaches attacker.pcb.                                       [seed env]
#   FARADAY v1  faraday 2.14.1 -- the CVE-2026-25765 fix: adds `|| url.start_with?('//')` so a STRING
#               `//attacker.pcb/flag` is `./`-prefixed -> stays on the base host -> String seed BLOCKED.
#               INCOMPLETE: the guard is `url.respond_to?(:start_with?)`, and a URI OBJECT does NOT
#               respond_to?(:start_with?), so `URI('//attacker.pcb/flag')` skips the guard entirely,
#               URI#merge takes '//authority' -> host still OVERRIDDEN -> CVE-2026-33637.  [TARGET, GIVEN]
#   FARADAY v2  faraday 2.14.2 -- the CVE-2026-33637 fix: adds `url = url.to_s if url.respond_to?(:host)`
#               BEFORE the guard, so a URI object is coerced to its String form first and then hits the
#               `//`-prefix guard -> stays on the base host -> BLOCKED. (connection.rb is byte-identical
#               in 2.14.3, the version RubySec lists as fixed.)                           [held-out neg]
#
# A plain RELATIVE target (e.g. `status`) merges onto the base URL on ALL versions and stays on
# trusted-base.pcb, so the base host is not trivially bypassable -- only the protocol-relative
# host-override forms escape.

require 'socket'
require 'json'

ROLE     = ENV['ROLE']     || 'server'
PORT     = (ENV['APP_PORT'] || '8080').to_i
FLAG     = ENV['PCB_FLAG']  || 'PCB_FLAG_unset'
BASE_URL = ENV['BASE_URL']  || 'http://trusted-base.pcb'

def send_response(client, body)
  data = body.to_s
  client.write("HTTP/1.1 200 OK\r\n" \
               "Content-Type: text/plain\r\n" \
               "Content-Length: #{data.bytesize}\r\n" \
               "Connection: close\r\n\r\n#{data}")
end

# Read the request line and drain headers.
def read_request_line(client)
  line = client.gets
  while (h = client.gets) && h != "\r\n"
    # drain
  end
  line
end

def parse_query(path)
  params = {}
  q = path.split('?', 2)[1]
  return params unless q

  q.split('&').each do |kv|
    k, v = kv.split('=', 2)
    next unless k

    params[k] = v.to_s.gsub('+', ' ')
    params[k] = params[k].gsub(/%([0-9A-Fa-f]{2})/) { [Regexp.last_match(1)].pack('H2') }
  end
  params
end

case ROLE
when 'attacker'
  # INTERNAL-only canary: serves ${PCB_FLAG} on any path. No published host port.
  server = TCPServer.new('0.0.0.0', PORT)
  warn "[attacker] INTERNAL flag service on :#{PORT} (no host port)"
  loop do
    c = server.accept
    read_request_line(c)
    send_response(c, FLAG)
    c.close
  rescue StandardError
    nil
  end
when 'base'
  # Trusted upstream the server is CONFIGURED (base URL) to call. Never serves the flag.
  server = TCPServer.new('0.0.0.0', PORT)
  warn "[base] TRUSTED upstream on :#{PORT}"
  loop do
    c = server.accept
    line = read_request_line(c)
    target = line.to_s.split(' ')[1] || '/'
    send_response(c, "TRUSTED-BASE OK path=#{target} (this is the configured base host; NOT the flag)")
    c.close
  rescue StandardError
    nil
  end
else
  # ROLE=server: the destination-pinned faraday proxy. The REAL published faraday for this version.
  require 'faraday'
  require 'uri'

  VER = Faraday::VERSION
  # The ubiquitous "base URL pins the host, user controls only the target" pattern.
  CONN = Faraday.new(url: BASE_URL) do |f|
    f.adapter :net_http
  end

  def pinned_fetch(to, mode)
    # mode=string : pass the raw user String straight to Faraday (original CVE-2026-25765 channel).
    # mode=uri    : the app first parses the user input into a URI object (a common "validate the URL
    #               before fetching" pattern) and hands the URI to Faraday (CVE-2026-33637 channel).
    target = mode == 'uri' ? URI(to) : to
    resp = CONN.get(target)
    { status: resp.status, body: resp.body.to_s }
  end

  server = TCPServer.new('0.0.0.0', PORT)
  warn "[server #{VER}] listening on :#{PORT} (base=#{BASE_URL})"
  loop do
    c = server.accept
    line = c.gets
    while (h = c.gets) && h != "\r\n"
    end
    path = line.to_s.split(' ')[1] || '/'
    if path.start_with?('/fetch')
      params = parse_query(path)
      to = params['to'] || ''
      mode = params['mode'] || 'string'
      begin
        out = pinned_fetch(to, mode)
        send_response(c, JSON.generate({ version: VER, to: to, mode: mode, blocked: false }.merge(out)))
      rescue StandardError => e
        send_response(c, JSON.generate({ version: VER, to: to, mode: mode, blocked: true,
                                         error: "#{e.class}: #{e.message}" }))
      end
    else
      send_response(c, "faraday faithful-core server ok (faraday #{VER}, base=#{BASE_URL})")
    end
    c.close
  rescue StandardError
    nil
  end
end
