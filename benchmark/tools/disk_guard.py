#!/usr/bin/env python3
"""Disk watermark guard: every 5 min, if free space < 25GB, remove dangling
images + oldest unused pcb-* images until free > 35GB. Logs actions."""
import shutil
import subprocess
import time
import os

LOG = '/tmp/oc_ctx/disk_guard.log'


def free_gb():
    t = shutil.disk_usage('/')
    return t.free / 1e9


def run(cmd):
    subprocess.run(cmd, capture_output=True, text=True,
                   env={**os.environ, 'DOCKER_CONFIG': '/tmp/pcb_docker_config'})


def main():
    while True:
        free = free_gb()
        if free < 25:
            with open(LOG, 'a') as f:
                f.write(f'{time.strftime("%H:%M")} free={free:.1f}GB -> cleaning\n')
            # 1) dangling images
            run(['docker', 'image', 'prune', '-f'])
            # 2) oldest unused pcb-* images (by creation time), until enough
            for _ in range(40):
                free = free_gb()
                if free > 35:
                    break
                p = subprocess.run(
                    ['docker', 'images', '--filter', 'dangling=false', '--format',
                     '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedSince}}'],
                    capture_output=True, text=True,
                    env={**os.environ, 'DOCKER_CONFIG': '/tmp/pcb_docker_config'})
                lines = [l for l in (p.stdout or '').splitlines()
                         if ('pcb-' in l or 'pcb_' in l) and 'months ago' in l]
                if not lines:
                    lines = [l for l in (p.stdout or '').splitlines()
                             if ('pcb-' in l or 'pcb_' in l) and 'weeks ago' in l]
                if not lines:
                    break
                img = lines[0].split()[0]
                run(['docker', 'rmi', img])
                with open(LOG, 'a') as f:
                    f.write(f'  removed {img}\n')
        time.sleep(300)


if __name__ == '__main__':
    main()
