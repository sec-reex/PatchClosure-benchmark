ActionController::Routing::Routes.draw do |map|
  # GET /            -> benign warmup (still dispatched: CgiRequest#initialize runs,
  #                     which is where the CVE-2007-6077 shared-constant mutation happens)
  map.connect '', :controller => 'canary', :action => 'index'
  # GET /seed  -> attacker mints a valid (existing) session id to fixate with
  map.connect 'seed', :controller => 'canary', :action => 'seed'
  # GET /login?user=..&_session_id=..  -> victim authenticates (session sink)
  map.connect 'login', :controller => 'canary', :action => 'login'
  # GET /protected   -> the ${PCB_FLAG}-gated resource (session sink)
  map.connect 'protected', :controller => 'canary', :action => 'access'
  map.connect ':controller/:action/:id'
end
