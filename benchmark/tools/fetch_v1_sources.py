#!/usr/bin/env python3
"""Resolve every case to a git clone URL + tag, then shallow-clone v1 source.

Usage: python3 fetch_v1_git.py [--dry-run] [--only PCBV2-XXXX,...] [--concurrency N]

Reads case.yaml source.repo + source.v1 for each case.
Outputs to benchmark/v1_sources/<slug>/.
Skips cases that already have a populated cache.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
CASES_DIR = REPO / "benchmark" / "cases"
CACHE_DIR = REPO / "benchmark" / "v1_sources"

# Manual overrides for cases whose case.yaml repo field isn't a direct git URL
GIT_OVERRIDES = {
    # Tag naming fixes (repo URL auto-resolved from case.yaml, but tags differ)
    "PCBV2-0004": ("https://github.com/FasterXML/jackson-databind.git", ["jackson-databind-2.8.11"]),
    "PCBV2-0013": ("https://github.com/FasterXML/jackson-databind.git", ["jackson-databind-2.9.3"]),
    "PCBV2-0128": ("https://github.com/FasterXML/jackson-databind.git", ["jackson-databind-2.8.9"]),
    "PCBV2-0018": ("https://github.com/go-gitea/gitea.git", ["v1.26.1"]),
    "PCBV2-0117": ("https://github.com/go-gitea/gitea.git", ["v1.26.1"]),
    "PCBV2-0118": ("https://github.com/go-gitea/gitea.git", ["v1.16.5"]),
    "PCBV2-0036": ("https://github.com/siyuan-note/siyuan.git", ["v3.5.10"]),
    "PCBV2-0031": ("https://github.com/withastro/astro.git", ["astro@7.0.4"]),
    "PCBV2-0081": ("https://github.com/withastro/astro.git", ["@astrojs/cloudflare@13.1.9"]),
    "PCBV2-0103": ("https://github.com/django/django.git", ["1.8"]),
    "PCBV2-0130": ("https://github.com/jenkinsci/jenkins.git", ["jenkins-2.492.2", "stable-2.492.2"]),
    "PCBV2-0149": ("https://github.com/netty/netty.git", ["netty-4.1.43.Final"]),
    "PCBV2-0186": ("https://github.com/apache/rocketmq.git", ["rocketmq-all-5.1.1"]),
    "PCBV2-0192": ("https://github.com/steveukx/git-js.git", ["simple-git@3.35.2"]),
    "PCBV2-0123": ("https://github.com/gradio-app/gradio.git", ["gradio@4.11.0", "v4.11.0"]),
    "PCBV2-0183": ("https://github.com/adobe/css-tools.git", ["v4.3.1", "4.3.1", "main"]),
    # Tag-based refs
    "PCBV2-0028": ("https://github.com/TestLinkOpenSourceTRMS/testlink-code.git", ["1.9.19"]),
    "PCBV2-0064": ("https://github.com/apache/ofbiz-framework.git", ["release18.12.16", "release18.12"]),
    "PCBV2-0082": ("https://github.com/WWBN/AVideo.git", ["14.3", "14.2"]),
    "PCBV2-0151": ("https://github.com/Calcium-Ion/new-api.git", ["v0.9.0.5"]),
    # Manual repo URL mappings
    "PCBV2-0015": ("https://github.com/postcss/postcss.git", ["8.2.10"]),
    "PCBV2-0032": ("https://github.com/perl5-dbi/dbi.git", ["1.648"]),
    "PCBV2-0034": ("https://github.com/keras-team/keras.git", ["v3.13.2", "3.13.2"]),
    "PCBV2-0055": ("https://github.com/apache/lucene-solr.git", ["releases/lucene-solr/4.1.0"]),
    "PCBV2-0058": ("https://github.com/frappe/frappe.git", ["v15.58.0", "15.58.0"]),
    "PCBV2-0059": ("https://github.com/hapifhir/org.hl7.fhir.core.git", ["6.9.7"]),
    "PCBV2-0067": ("https://github.com/jenkinsci/remoting.git", ["remoting-2.53", "2.53"]),
    "PCBV2-0095": ("https://github.com/dataease/dataease.git", ["v2.10.23"]),
    "PCBV2-0105": ("https://github.com/rack/rack.git", ["v3.1.20", "3.1.20"]),
    "PCBV2-0133": ("https://github.com/keycloak/keycloak.git", ["24.0.3"]),
    "PCBV2-0184": ("https://github.com/django/django.git", ["4.2.6"]),
    "PCBV2-0188": ("https://github.com/ruby/ruby.git", ["v2_1_4", "v2.1.4"]),
    "PCBV2-0214": ("https://github.com/xwiki/xwiki-platform.git", ["xwiki-platform-16.10.16"]),
    # SourceForge / non-git — use per-case fetch_source.sh
    "PCBV2-0154": "fetch_source",  # SourceForge NukeSentinel (local_tgz)
    "PCBV2-0181": "fetch_source",  # SourceForge qdPM (url_tgz zip)
    "PCBV2-0207": "fetch_source",  # SourceForge TWiki (url_tgz)
    # ------------------------------------------------------------------
    # v1_source root cause audit 2026-10-21: 63 new overrides
    # Tags verified against actual case.yaml V1 values.
    # ------------------------------------------------------------------
    # Bucket A: git TYPE — monorepo tag, wrong repo, incomplete clone,
    #           JAR/npm/composer extract → re-clone from correct repo+tag
    # ------------------------------------------------------------------
    "PCBV2-0003": ("https://github.com/vitejs/vite.git", ["v5.4.15", "create-vite@5.4.15"]),
    "PCBV2-0005": ("https://github.com/x-stream/xstream.git", ["XSTREAM_1_4_13", "v-1.4.13"]),  # V1=1.4.13
    "PCBV2-0006": ("https://github.com/python/cpython.git", ["v3.7.4"]),
    "PCBV2-0011": ("https://github.com/drupal/drupal.git", ["8.5.1"]),
    "PCBV2-0029": ("https://github.com/ruby/webrick.git", ["v1.4.2"]),  # standalone repo, not ruby/ruby
    "PCBV2-0033": ("https://github.com/gogs/gogs.git", ["v0.14.2"]),  # V1=0.14.2 from docker-compose
    "PCBV2-0035": ("https://github.com/nodejs/node.git", ["v20.15.1"]),
    "PCBV2-0041": ("https://github.com/alibaba/fastjson.git", ["1.2.25"]),
    "PCBV2-0043": ("https://github.com/mozilla/node-convict.git", ["convict@6.2.2", "v6.2.2"]),
    "PCBV2-0049": ("https://github.com/apache/mina.git", ["2.2.4"]),
    "PCBV2-0053": ("https://github.com/nahsra/antisamy.git", ["v1.7.4"]),
    "PCBV2-0054": ("https://github.com/apache/dubbo.git", ["dubbo-2.7.8"]),
    "PCBV2-0056": ("https://github.com/withastro/astro.git", ["astro@5.13.4"]),  # V1=5.13.4 from Dockerfile
    "PCBV2-0060": ("https://github.com/hapifhir/org.hl7.fhir.core.git", ["5.6.92"]),
    "PCBV2-0062": ("https://github.com/lukeed/dset.git", ["3.1.2", "v3.1.2"]),
    "PCBV2-0066": ("https://github.com/nahsra/antisamy.git", ["v1.6.6"]),
    "PCBV2-0078": ("https://github.com/apache/shiro.git", ["shiro-root-1.5.3", "1.5.3"]),
    "PCBV2-0089": ("https://github.com/yaml/pyyaml.git", ["5.3.1"]),
    "PCBV2-0092": ("https://github.com/CycloneDX/cyclonedx-core-java.git", ["cyclonedx-core-java-9.0.4"]),
    "PCBV2-0102": ("https://github.com/yiisoft/yii2.git", ["2.0.50"]),
    "PCBV2-0108": ("https://github.com/nearform/fast-jwt.git", ["v3.3.2"]),  # V1=3.3.2 from docker-compose
    "PCBV2-0115": ("https://github.com/frangoteam/FUXA.git", ["v1.2.10"]),
    "PCBV2-0126": ("https://github.com/handlebars-lang/handlebars.js.git", ["v4.7.6"]),
    "PCBV2-0138": ("https://github.com/locutusjs/locutus.git", ["v2.0.39", "2.0.39"]),
    "PCBV2-0150": ("https://github.com/netty/netty.git", ["netty-4.1.129.Final"]),
    "PCBV2-0155": ("https://github.com/nuxt-modules/og-image.git", ["v6.2.5"]),
    "PCBV2-0164": ("https://github.com/parse-community/parse-server.git", ["6.5.0"]),
    "PCBV2-0169": ("https://github.com/PHPMailer/PHPMailer.git", ["v5.2.18"]),
    "PCBV2-0170": ("https://github.com/thorsten/phpMyFAQ.git", ["4.1.3"]),
    "PCBV2-0185": ("https://github.com/resteasy/resteasy.git", ["3.0.8.Final"]),
    "PCBV2-0191": ("https://github.com/steveukx/git-js.git", ["simple-git@3.31.1"]),
    "PCBV2-0199": ("https://github.com/peerigon/angular-expressions.git", ["v1.0.1", "1.0.1"]),  # V1=1.0.1
    "PCBV2-0201": ("https://github.com/n8n-io/n8n.git", ["n8n@1.122.0", "1.122.0"]),  # V1=n8n 1.122.0
    # ------------------------------------------------------------------
    # Bucket B: docker_image TYPE — Docker Hub/ghcr.io → GitHub mapping
    # ------------------------------------------------------------------
    "PCBV2-0001": ("https://github.com/eclipse/jetty.project.git", ["jetty-9.4.39.v20210325"]),
    "PCBV2-0019": ("https://github.com/pgadmin-org/pgadmin4.git", ["REL-9_16"]),
    "PCBV2-0045": ("https://github.com/apache/superset.git", ["4.0.2"]),
    "PCBV2-0080": ("https://github.com/ArcadeData/arcadedb.git", ["26.4.2"]),
    "PCBV2-0086": ("https://github.com/Budibase/budibase.git", ["3.32.0"]),
    "PCBV2-0121": ("https://github.com/gogs/gogs.git", ["v0.13.3"]),
    "PCBV2-0124": ("https://github.com/grafana/grafana.git", ["v8.3.1"]),
    "PCBV2-0129": ("https://github.com/jenkinsci/jenkins.git", ["jenkins-2.176.2"]),
    "PCBV2-0135": ("https://github.com/koel/koel.git", ["v9.3.5"]),
    "PCBV2-0136": ("https://github.com/danny-avila/LibreChat.git", ["v0.7.6"]),
    "PCBV2-0137": ("https://github.com/danny-avila/LibreChat.git", ["v0.7.9"]),
    "PCBV2-0159": ("https://github.com/openremote/openremote.git", ["1.22.0"]),
    "PCBV2-0165": ("https://github.com/pgadmin-org/pgadmin4.git", ["REL-9_16"]),
    "PCBV2-0166": ("https://github.com/pgadmin-org/pgadmin4.git", ["REL-9_16"]),
    "PCBV2-0168": ("https://github.com/php/php-src.git", ["php-8.1.11"]),
    "PCBV2-0193": ("https://github.com/siyuan-note/siyuan.git", ["v3.5.9"]),
    "PCBV2-0194": ("https://github.com/siyuan-note/siyuan.git", ["v3.5.9"]),
    "PCBV2-0195": ("https://github.com/siyuan-note/siyuan.git", ["v3.6.5"]),
    # ------------------------------------------------------------------
    # Bucket C: maven/npm TYPE — git clone instead of JAR/tarball extract
    # Tags from actual case.yaml V1 values (corrected from root cause estimates)
    # ------------------------------------------------------------------
    "PCBV2-0068": ("https://github.com/apache/dolphinscheduler.git", ["3.1.9"]),
    "PCBV2-0077": ("https://github.com/apache/logging-log4j2.git", ["rel/2.15.0"]),  # V1=2.15.0
    "PCBV2-0079": ("https://github.com/apache/struts.git", ["STRUTS_2_5_26"]),  # V1=2.5.26
    "PCBV2-0099": ("https://github.com/apache/mina.git", ["2.2.6"]),  # V1=2.2.6
    "PCBV2-0163": ("https://github.com/OWASP/java-html-sanitizer.git", ["release-20211018.1"]),  # V1=20211018.1
    "PCBV2-0173": ("https://github.com/spring-projects/spring-integration-extensions.git", ["zip.v1.0.1.RELEASE"]),
    "PCBV2-0174": ("https://github.com/codehaus-plexus/plexus-archiver.git", ["plexus-archiver-3.6.0"]),  # V1=3.6.0
    "PCBV2-0196": ("https://github.com/spring-projects/spring-framework.git", ["v5.3.17"]),  # V1=5.3.17
    "PCBV2-0197": ("https://github.com/spring-projects/spring-framework.git", ["v6.1.5"]),  # V1=6.1.5
    "PCBV2-0202": ("https://github.com/thymeleaf/thymeleaf.git", ["thymeleaf-3.1.4.RELEASE"]),  # V1=3.1.4.RELEASE
    # ------------------------------------------------------------------
    # Bucket D: url_tgz/zip — git clone instead of tarball extraction
    # ------------------------------------------------------------------
    "PCBV2-0119": ("https://github.com/glpi-project/glpi.git", ["10.0.14"]),  # V1=10.0.14
    # SourceForge-only (Bucket E boundary) — needs custom fetch_source.sh
    "PCBV2-0007": "fetch_source",  # SourceForge vtiger CRM
    # ------------------------------------------------------------------
    # Coverage fix round 2: cases where v1_source had wrong content or npm dist instead of git src
    # ------------------------------------------------------------------
    "PCBV2-0061": ("https://github.com/keystonejs/keystone.git", ["@keystone-6/core@6.5.1"]),  # monorepo scoped tag
    "PCBV2-0148": ("https://github.com/rs/node-netmask.git", ["2.0.0"]),  # npm dist had no lib/*.coffee
    "PCBV2-0152": ("https://github.com/vercel/next.js.git", ["v15.5.16"]),  # npm pack misses src/
}


def get_slug(eid: str) -> str:
    cj = CASES_DIR / eid / "case.json"
    if cj.exists():
        return json.load(open(cj)).get("case_id", eid)
    return eid


def resolve_source(eid: str) -> tuple[str | None, list[str]]:
    """Return (git_url, tag_candidates) for a case. 'fetch_source' sentinel uses per-case script."""
    if eid in GIT_OVERRIDES:
        override = GIT_OVERRIDES[eid]
        if override is None:
            return None, []
        if override == "fetch_source":
            return "fetch_source", []
        return override

    cy = CASES_DIR / eid / "case.yaml"
    if not cy.exists():
        return None, []
    data = yaml.safe_load(cy.read_text())
    src = data.get("source", {})
    repo = str(src.get("repo", "") or "")
    v1 = str(src.get("v1", "") or "")
    stype = src.get("type", "")

    if not repo or not v1:
        return None, []

    # Build git URL
    git_url = None
    if "github.com" in repo or "gitlab" in repo:
        git_url = repo if repo.startswith("http") else f"https://{repo}"
        if not git_url.endswith(".git"):
            git_url += ".git"
    elif stype == "docker_image" and "/" in repo and "registry" not in repo and "quay" not in repo:
        git_url = f"https://github.com/{repo}.git"
    elif stype == "composer" and "/" in repo:
        git_url = f"https://github.com/{repo}.git"
    elif stype in ("npm",) and "/" not in repo:
        return None, []

    if not git_url:
        return None, []

    # Build tag candidates
    tags = [v1]
    if not v1.startswith("v"):
        tags.append(f"v{v1}")
    if "@" in v1:
        bare = v1.split("@")[-1]
        tags.extend([bare, f"v{bare}"])
    return git_url, tags


def _lock_readonly(path: Path):
    """Remove write permission from all files/dirs so symlinked contestants can't corrupt shared source."""
    subprocess.run(["chmod", "-R", "a-w", str(path)], capture_output=True)


def clone_v1(eid: str, slug: str, git_url: str, tags: list[str]) -> tuple[str, bool, str]:
    """Clone into benchmark/v1_sources/<slug>/. Returns (eid, success, message)."""
    dest = CACHE_DIR / slug
    if dest.exists() and any(dest.iterdir()):
        return eid, True, "already cached"

    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        subprocess.run(["chmod", "-R", "u+w", str(dest)], capture_output=True)
        shutil.rmtree(dest)

    if git_url == "fetch_source":
        script = CASES_DIR / eid / "scripts" / "fetch_source.sh"
        if not script.exists():
            return eid, False, "fetch_source.sh not found"
        r = subprocess.run(
            ["bash", str(script), "--version", "v1", "--dest", str(dest)],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode == 0 and dest.exists() and any(dest.iterdir()):
            git_dir = dest / ".git"
            if git_dir.exists():
                shutil.rmtree(git_dir)
            _lock_readonly(dest)
            nfiles = sum(1 for _ in dest.rglob("*") if _.is_file())
            return eid, True, f"fetch_source.sh, {nfiles} files"
        return eid, False, f"fetch_source.sh exit={r.returncode}: {r.stderr[:200]}"

    for tag in tags:
        cmd = [
            "git", "clone", "--depth", "1", "--branch", tag,
            "--single-branch", "--no-tags",
            git_url, str(dest),
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            git_dir = dest / ".git"
            if git_dir.exists():
                shutil.rmtree(git_dir)
            _lock_readonly(dest)
            nfiles = sum(1 for _ in dest.rglob("*") if _.is_file())
            return eid, True, f"cloned tag={tag}, {nfiles} files"
        # Tag might not exist, try next
    return eid, False, f"all tags failed: {tags} from {git_url}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--only", help="Comma-separated eval_ids")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--missing-only", action="store_true", default=True,
                        help="Skip cases that already have cached v1 source")
    parser.add_argument("--force-overrides", action="store_true",
                        help="Re-fetch cases that have GIT_OVERRIDES even if cached (deletes old content)")
    args = parser.parse_args()

    eids = sorted(d.name for d in CASES_DIR.iterdir() if d.name.startswith("PCBV2-"))
    if args.only:
        only_set = set(args.only.split(","))
        eids = [e for e in eids if e in only_set]

    tasks = []
    skipped = 0
    no_git = []
    for eid in eids:
        slug = get_slug(eid)
        if args.missing_only:
            dest = CACHE_DIR / slug
            if dest.exists() and any(dest.iterdir()):
                if args.force_overrides and eid in GIT_OVERRIDES and GIT_OVERRIDES[eid] not in (None, "fetch_source"):
                    import shutil
                    print(f"  {eid}: force-override — deleting old v1_sources/{slug}")
                    shutil.rmtree(dest, ignore_errors=True)
                else:
                    skipped += 1
                    continue

        git_url, tags = resolve_source(eid)
        if not git_url:
            no_git.append(eid)
            continue
        tasks.append((eid, slug, git_url, tags))  # git_url may be "fetch_source"

    print(f"Cases: {len(eids)}, already cached: {skipped}, to clone: {len(tasks)}, no git URL: {len(no_git)}")
    if no_git:
        print(f"  No git URL: {', '.join(no_git)}")

    if args.dry_run:
        for eid, slug, git_url, tags in tasks:
            print(f"  {eid} ({slug}): {git_url} tags={tags}")
        return

    ok = 0
    fail = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(clone_v1, eid, slug, git_url, tags): eid
                   for eid, slug, git_url, tags in tasks}
        for future in as_completed(futures):
            eid, success, msg = future.result()
            status = "OK" if success else "FAIL"
            print(f"  [{status}] {eid}: {msg}")
            if success:
                ok += 1
            else:
                fail += 1

    print(f"\nDone: {ok} cloned, {fail} failed, {skipped} already cached, {len(no_git)} no git URL")


if __name__ == "__main__":
    main()
