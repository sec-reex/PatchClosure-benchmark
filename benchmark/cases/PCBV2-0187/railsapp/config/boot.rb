# Real Rails 1.2 boot: activate the vendored rails gem (and its deps) and load the
# actual railties Initializer. No app code lifts actionpack -- the real gem runs.
require 'rubygems'
gem 'rails'
require 'initializer'
