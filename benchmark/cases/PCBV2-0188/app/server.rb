#!/usr/bin/env ruby
# frozen_string_literal: false
#
# REAL Ruby web app for PatchClosure-Bench ruby-rexml-cve-2014-8090.
#
# A minimal WEBrick HTTP service (WEBrick ships in the Ruby stdlib of every 2.1.x
# release) that parses a user-supplied XML document with the REAL bundled REXML of
# the Ruby version this container runs (2.1.3 / 2.1.4 / 2.1.5 -> the exact REXML
# shipped in MRI at that patch level). This mirrors a real Ruby app that accepts XML
# over HTTP (SOAP/config/upload endpoints) and parses it with the stdlib parser.
#
#   POST /parse   body = raw XML  ->  require 'rexml/document'; REXML::Document.new(body)
#
# The parse runs SYNCHRONOUSLY inside the request handler, so a billion-laughs /
# parameter-entity expansion bomb blows up CPU (and/or memory) and HANGS the HTTP
# response -> server-side DoS observable as EXTERNAL request latency. REXML keeps its
# stock 2014 defaults (entity_expansion_limit=10000, entity_expansion_text_limit=10240);
# we do NOT relax them.
#
#   GET  /health  ->  {"ok":true, ...}
#
require 'webrick'
require 'json'
require 'rexml/document'
require 'rexml/security'

PORT = (ENV['PORT'] || '3000').to_i

REXML_VER = (defined?(REXML::VERSION) ? REXML::VERSION : 'n/a')

def parse_verdict(xml)
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  status = 'parsed'
  err = nil
  begin
    doc = REXML::Document.new(xml)
    # Full consumption, exactly what an app reading attacker XML does: walk the tree
    # and force lazy text/entity expansion.
    total = 0
    doc.each_recursive do |n|
      total += n.text.to_s.bytesize if n.respond_to?(:text)
    end
  rescue NoMemoryError
    status = 'oom'
  rescue RuntimeError => e
    m = e.message.to_s
    if m.include?('entity expansion has grown too large') ||
       m.include?('number of entity expansions exceeded')
      status = 'limited'          # a REXML guard fired -> DEFENDED
      err = m[0, 160]
    else
      status = 'error'
      err = m[0, 160]
    end
  rescue Exception => e
    status = 'error'
    err = "#{e.class}: #{e.message}"[0, 160]
  end
  ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round(1)
  { status: status, server_ms: ms, len: xml.bytesize, err: err,
    ruby: RUBY_VERSION, rexml: REXML_VER }
end

server = WEBrick::HTTPServer.new(
  Port: PORT,
  BindAddress: '0.0.0.0',
  Logger: WEBrick::Log.new(File::NULL),
  AccessLog: []
)

server.mount_proc '/health' do |req, res|
  res.status = 200
  res['Content-Type'] = 'application/json'
  res.body = JSON.generate({ ok: true, ruby: RUBY_VERSION, rexml: REXML_VER })
end

server.mount_proc '/parse' do |req, res|
  xml = req.body.to_s
  verdict = parse_verdict(xml)      # <-- synchronous REXML entity-expansion sink
  res.status = 200
  res['Content-Type'] = 'application/json'
  res.body = JSON.generate(verdict)
end

trap('INT')  { server.shutdown }
trap('TERM') { server.shutdown }

STDOUT.sync = true
puts "rexml-parse app listening on :#{PORT} (ruby #{RUBY_VERSION}, rexml #{REXML_VER})"
server.start
