# Production: cache classes, hide raw error pages (a SessionFixationAttempt renders the
# generic 500, never leaking anything). The canary is served only by the /protected action.
config.cache_classes = true
config.action_controller.consider_all_requests_local = false
config.action_view.cache_template_extensions = false rescue nil
