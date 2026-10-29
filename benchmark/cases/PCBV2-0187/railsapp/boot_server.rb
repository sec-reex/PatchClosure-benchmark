# Real Rails 1.2 WEBrick launcher -- a faithful copy of railties'
# lib/commands/servers/webrick.rb entry: load the app environment, then hand off to the
# REAL railties DispatchServlet (lib/webrick_server.rb), which per request calls
# Dispatcher.dispatch(cgi, ActionController::CgiRequest::DEFAULT_SESSION_OPTIONS, ...).
# That shared-constant argument is exactly what CVE-2007-6077 mutates. No sink is lifted.
require 'webrick'

ENV['RAILS_ENV'] ||= 'production'
RAILS_ROOT = File.expand_path(File.dirname(__FILE__)) unless defined?(RAILS_ROOT)

require File.join(RAILS_ROOT, 'config', 'environment')
require 'webrick_server'

OPTIONS = {
  :port               => Integer(ENV['PCB_PORT'] || 8080),
  :ip                 => '0.0.0.0',
  :environment        => ENV['RAILS_ENV'],
  :server_root        => File.expand_path(RAILS_ROOT + '/public/'),
  :server_type        => WEBrick::SimpleServer,
  :charset            => 'UTF-8',
  :mime_types         => WEBrick::HTTPUtils::DefaultMimeTypes,
  'working_directory' => File.expand_path(RAILS_ROOT),
}

$stdout.puts "rails-app up env=#{ENV['RAILS_ENV']} port=#{OPTIONS[:port]} " \
             "rails=#{Rails::VERSION::STRING} flag_set=#{!ENV['PCB_FLAG'].to_s.empty?}"
$stdout.flush

DispatchServlet.dispatch(OPTIONS)
