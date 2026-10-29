#!/usr/bin/env python3
"""ROUND17: backfill B-class (agent-searched) entries in source_manifest.json."""
import json, os

MF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'provenance', 'source_manifest.json')
m = json.load(open(MF))

B = {
 'astro-image-isremotepath': ('https://github.com/withastro/astro',
    'astro@5.13.1', 'astro@5.13.4', 'astro@5.13.10'),
 'cockpit-cve-2018-9302': ('https://github.com/agentejo/cockpit',
    'a5fb51cb51178ef330be3db45eb583621e9891d0', '0711d4f9dd6d38d834141d619d6fe141ca146f2f',
    '279e6690'),
 'codeinj_pyyaml_fullloader': ('https://github.com/yaml/pyyaml', '5.3', '5.3.1', '5.4'),
 'fast-jwt-cve-2026-34950': ('https://github.com/nearform/fast-jwt', 'v3.3.1', 'v3.3.2', 'v6.2.0'),
 'glpi-search-constructsql-sqli': ('https://github.com/glpi-project/glpi', '10.0.12', '10.0.14', '10.0.15'),
 'gogs-cve-2025-64111': ('https://github.com/gogs/gogs', 'v0.13.2', 'v0.13.3', 'v0.13.4'),
 'gogs-cve-2026-47267': ('https://github.com/gogs/gogs', 'v0.12.7', 'v0.14.2', 'v0.14.3'),
 'jetty-uri-canonicalize-before-authz-webinf': ('https://github.com/jetty/jetty.project',
    'jetty-9.4.38.v20210224', 'jetty-9.4.39.v20210325', 'jetty-9.4.43.v20210629'),
 'keystone6-cve-2026-33326': ('https://github.com/keystonejs/keystone',
    '@keystone-6/core@6.4.0', '@keystone-6/core@6.5.1', '@keystone-6/core@6.5.2'),
 'nuxt-og-image-isblockedurl': ('https://github.com/nuxt-modules/og-image', 'v6.2.4', 'v6.2.5', 'v6.4.9'),
 'spring-framework-cve-2022-22965': ('https://github.com/spring-projects/spring-framework',
    'v5.3.17', 'v5.3.17', 'v5.3.18'),
 'spring-framework-cve-2024-22262': ('https://github.com/spring-projects/spring-framework',
    'v6.1.4', 'v6.1.5', 'v6.1.6'),
 'ssti_angular_expressions_constructor': ('https://github.com/peerigon/angular-expressions',
    'v1.0.0', 'v1.0.1', 'v1.1.2'),
 'ssti_jinjava_objectmapper_sandbox': ('https://github.com/HubSpot/jinjava',
    'jinjava-2.8.0', 'jinjava-2.8.1', 'jinjava-2.8.3'),
 'ssti_n8n_expression_sandbox': ('https://github.com/n8n-io/n8n', 'n8n@1.119.1', 'n8n@1.122.0', 'n8n@1.123.17'),
 'tomcat-cve-2021-25329': ('https://github.com/apache/tomcat', '9.0.34', '9.0.35', '9.0.43'),
 'xstream-cve-2020-26217': ('https://github.com/x-stream/xstream', 'XSTREAM_1_4_13', 'XSTREAM_1_4_13', 'XSTREAM_1_4_14'),
 'arcadedb-cve-2026-54076': ('https://github.com/ArcadeData/arcadedb', '26.3.2', '26.4.2', '26.6.1'),
 'openremote-cve-2026-54640': ('https://github.com/openremote/openremote', '1.21.0', '1.22.0', '1.24.2'),
 'faraday-cve-2026-33637': ('https://github.com/lostisland/faraday', 'v2.14.0', 'v2.14.1', 'v2.14.2'),
 'suitecrm-cve-2026-29103': ('https://github.com/salesagility/SuiteCRM', 'v7.14.5', 'v7.15.0', 'v7.15.1'),
}

n = 0
for cid, (repo, v0, v1, v2) in B.items():
    if cid not in m:
        print('MISSING', cid); continue
    e = m[cid]
    e['source_type'] = 'git'
    e['fetch_plan'] = 'sparse_git'
    locs = {'v0': v0, 'v1': v1, 'v2': v2}
    for ver, ref in locs.items():
        if not ref:
            continue
        e[ver]['source_type'] = 'git'
        e[ver]['sub_type'] = 'git'
        e[ver]['locator'] = {'repo_url': repo, 'ref': ref}
    n += 1
json.dump(m, open(MF, 'w'), ensure_ascii=False, indent=1)
print(f'backfilled B-class: {n} entries')
from collections import Counter
c = Counter(e['source_type'] for e in m.values())
print('distribution:', dict(c))
u = [cid for cid, e in m.items() if e['source_type'] == 'unresolved']
print('remaining unresolved:', len(u))
