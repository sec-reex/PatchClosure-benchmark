# frozen_string_literal: true
#
# REAL running Rack web app for the byte-range DoS case (CVE-2024-26141 -> CVE-2026-34826).
#
# A real HTTP server (WEBrick, driven through the published `rackup` handler) serves a ~900 KB
# static file via the REAL published `Rack::Files` middleware (pinned per profile to rack
# 3.0.9 / 3.1.20 / 3.1.21). GET /file honours the client `Range:` header: Rack::Files calls
# Rack::Utils.get_byte_ranges(env['HTTP_RANGE'], size) and assembles a multipart/byteranges
# 206 response with one part per range. The DoS is triggered by an EXTERNAL HTTP request whose
# crafted Range header makes get_byte_ranges + the multipart assembly do disproportionate work
# SERVER-SIDE. Rack itself is UNMODIFIED (installed from RubyGems); only the web-server config
# below is tuned.
#
# Server config (not app code, not Rack): WEBrick hard-codes a 112 KiB request-header limit
# (WEBrick::HTTPRequest::MAX_HEADER_LENGTH). A production deployment that accepts large Range
# headers is configured with a bigger limit (cf. nginx `large_client_header_buffers`); we raise
# it here so the server admits the crafted Range header and the request reaches the Rack sink.
require 'rack'
require 'rack/files'
require 'rackup/handler/webrick'
require 'fileutils'

MAX_HEADER_BYTES = (ENV['MAX_HEADER_BYTES'] || (8 * 1024 * 1024).to_s).to_i
if WEBrick::HTTPRequest.const_defined?(:MAX_HEADER_LENGTH)
  WEBrick::HTTPRequest.send(:remove_const, :MAX_HEADER_LENGTH)
end
WEBrick::HTTPRequest.const_set(:MAX_HEADER_LENGTH, MAX_HEADER_BYTES)

DATA_DIR  = ENV['DATA_DIR']  || '/data'
FILE_SIZE = (ENV['FILE_SIZE'] || '900000').to_i
FileUtils.mkdir_p(DATA_DIR)
FILE_PATH = File.join(DATA_DIR, 'file')
unless File.exist?(FILE_PATH) && File.size(FILE_PATH) == FILE_SIZE
  File.open(FILE_PATH, 'wb') { |f| f.write('A' * FILE_SIZE) }
end

# The REAL published Rack::Files middleware serves DATA_DIR; GET /file -> DATA_DIR/file, and it
# implements HTTP byte-range (partial content) responses via Rack::Utils.get_byte_ranges.
files = Rack::Files.new(DATA_DIR)

def gbr_signature
  Rack::Utils.method(:get_byte_ranges).parameters.map { |p| p.join(':') }.join(',')
rescue StandardError
  'n/a'
end

app = lambda do |env|
  case env['PATH_INFO']
  when '/health'
    loc = Rack::Files.instance_method(:call).source_location[0]
    [200, { 'content-type' => 'application/json' },
     ["{\"ok\":true,\"rack\":\"#{Rack.release}\",\"files\":\"#{loc}\"}"]]
  when '/sig'
    # metadata only: report the live Rack::Utils.get_byte_ranges signature (reflection, no DoS)
    [200, { 'content-type' => 'application/json' },
     ["{\"rack\":\"#{Rack.release}\",\"get_byte_ranges_sig\":\"#{gbr_signature}\"}"]]
  else
    files.call(env)     # GET /file  -> Rack::Files (honours Range: header -> the DoS sink)
  end
end

PORT = (ENV['PORT'] || '3000').to_i
logger = WEBrick::Log.new($stderr, WEBrick::Log::WARN)
$stderr.puts "rack-files server: rack #{Rack.release} on :#{PORT} (max_header=#{MAX_HEADER_BYTES})"
Rackup::Handler::WEBrick.run(app, Host: '0.0.0.0', Port: PORT, Logger: logger, AccessLog: [])
