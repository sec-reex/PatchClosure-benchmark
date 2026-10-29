# BUILD_TODO — gradio-file-endpoint-is-in-or-equal-bypass

- [x] Resolve V0=4.10.0, V1=4.11.0 (CVE-2023-51449 fix, target), V2=5.0.0 (CVE-2024-47164 fix)
- [x] Confirm same sink is_in_or_equal evolution across all three (source-verified)
- [x] Dockerfile pip install gradio==<ver> + era-pinned deps; minimal gr.Interface app; allowed_paths=["/gradio_tmp"]
- [x] Canary /flag planted OUTSIDE allowed dir by compose entrypoint from ${PCB_FLAG}
- [x] original_poc.py = /file=/gradio_tmp/sub/../../flag (subdir + ..)
- [x] _heldout/bypass_poc.py = /file=/gradio_tmp/escape/flag (symlink escape -> /)
- [x] Gate: original@V0 reaches, original@V1 blocked, residual@V1 reaches; V2 blocks both
- [x] Teardown down -v --rmi all + prune
