# Real Rails 1.2 environment. Only ActionPack/ActiveSupport frameworks are enabled
# (no database) so the app boots without ActiveRecord; the real ActionController
# CgiRequest session sink (actionpack/lib/action_controller/cgi_process.rb) still runs.
require File.join(File.dirname(__FILE__), 'boot')

# Rails 1.2's Initializer#load_observers unconditionally calls
# ActiveRecord::Base.instantiate_observers, so the constant must exist even when the
# ActiveRecord *framework* is disabled. Load the REAL activerecord gem (no fakes) purely
# so that hook is a no-op (@observers is empty). Because :active_record stays out of
# config.frameworks below, Initializer#initialize_database is skipped -> no DB, no adapter.
require 'active_record'

Rails::Initializer.run do |config|
  config.frameworks -= [:active_record, :action_mailer, :action_web_service]
  config.cache_classes = true
  config.log_level = :info
  # Leave session handling at the real Rails defaults so ActionController::CgiRequest
  # keeps its DEFAULT_SESSION_OPTIONS (PStore, :cookie_only => true on the patched
  # versions). Do NOT override -- the CVE lives in that default path.
end
