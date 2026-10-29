# Real Rails controller. Every action accesses `session`, driving the REAL
# ActionController::CgiRequest#session sink in actionpack/lib/action_controller/cgi_process.rb
# (the CVE-2007-5380 :cookie_only guard and the CVE-2007-6077 shared-constant residual live
# there, not here). The ${PCB_FLAG} is read from the process environment and disclosed only
# to a request whose session is authenticated.
class CanaryController < ApplicationController
  # Configure the session id parameter name at the app level. Rails 1.2.4's
  # DEFAULT_SESSION_OPTIONS ships WITHOUT :session_key, so the guard's
  # `request_parameters[session_key]` check would look up request_parameters[nil] and never
  # fire; a real app naming its session key is what makes the CVE-2007-5380 guard operative,
  # isolating the CVE-2007-6077 mutation as the only v1-vs-v2 difference. (Rails 1.2.6 later
  # hard-coded this same :session_key => "_session_id" into DEFAULT_SESSION_OPTIONS.)
  session :session_key => '_session_id'

  # GET /  -- benign warmup. Dispatched through Rails, so CgiRequest#initialize runs
  # (`@cookie_only = session_options.delete :cookie_only` mutates the shared constant on v1).
  def index
    render :text => "root ok\n"
  end

  # GET /seed  -- mint a fresh, real, server-side session WITHOUT authenticating it, and
  # hand its id back via Set-Cookie. This is the attacker obtaining a valid (existing)
  # session id to later fixate onto the victim. No _session_id is supplied here, so the id
  # is server-generated and its PStore file is persisted on disk.
  def seed
    session[:touched] = true
    render :text => "seeded\n"
  end

  # GET /login?user=victim&_session_id=<sid>
  # The victim authenticates. If the request carries a URL-supplied _session_id and the
  # :cookie_only guard is active, ActionController::CgiRequest raises SessionFixationAttempt
  # BEFORE this body runs (=> 500, nothing authenticated). Otherwise the URL-supplied id is
  # honored (fixation) and its session is marked authenticated.
  def login
    session[:user] = (params[:user] || 'victim').to_s
    session[:authenticated] = true
    render :text => "logged_in user=#{session[:user]}\n"
  end

  # GET /protected  -- the canary-gated resource. Readable only via an authenticated session.
  def access
    if session[:authenticated]
      render :text => "SECRET=#{ENV['PCB_FLAG']} user=#{session[:user]}\n"
    else
      render :text => "unauthorized (no authenticated session)\n", :status => 401
    end
  end
end
