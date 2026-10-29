# Minimal Puma config for the faithful-core CRLF case.
bind "tcp://0.0.0.0:9292"
early_hints true          # enables env['rack.early_hints'] -> the CVE-2020-5249 residual sink
workers 0                 # single mode, deterministic
threads 1, 4
