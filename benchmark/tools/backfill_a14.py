#!/usr/bin/env python3
"""ROUND17: backfill A-class (A1-A4) unresolved entries in source_manifest.json.

Coordinates are public locators supplied in the round brief / case refs.
No held-out fields touched; no per-case code beyond the locator table itself.
"""
import json, os

MF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  'provenance', 'source_manifest.json')
m = json.load(open(MF))

# A1 maven: case_id -> (gav, version)
MAVEN = {
    'antisamy_comment_mxss': ('org.owasp.antisamy:antisamy', '1.7.4'),
    'antisamy_style_smuggling': ('org.owasp.antisamy:antisamy', '1.6.6'),
    'apache-dolphinscheduler-cve-2024-23320': ('org.apache.dolphinscheduler:dolphinscheduler-master', '3.1.9'),
    'apache-dubbo-serializer-switch-cve-2021-25641': ('org.apache.dubbo:dubbo', '2.7.8'),
    'apache-log4j-2-cve-2021-45046': ('org.apache.logging.log4j:log4j-core', '2.15.0'),
    'apache-mina-cve-2026-42778': ('org.apache.mina:mina-core', '2.2.4'),
    'apache-shiro-cve-2020-13933': ('org.apache.shiro:shiro-core', '1.5.3'),
    'apache-struts-cve-2021-31805': ('org.apache.struts:struts2-core', '2.5.26'),
    'cyclonedx-cve-2025-64518': ('org.cyclonedx:cyclonedx-core-java', '9.0.4'),
    'deser_fastjson_autotype': ('com.alibaba:fastjson', '1.2.25'),
    'deser_mina_objser': ('org.apache.mina:mina-core', '2.2.6'),
    'hl7-fhir-org-hl7-fhir-core-cve-2023-28465': ('ca.uhn.hapi.fhir:org.hl7.fhir.r4b', '5.6.92'),
    'netty-cve-2026-42578': ('io.netty:netty-codec-http', '4.1.129.Final'),
    'pivotal-spring-integration-zip-cve-2018-1263': ('org.springframework.integration:spring-integration-zip', '1.0.1.RELEASE'),
    'plexus-archiver-symlink-extraction-bypass': ('org.codehaus.plexus:plexus-archiver', '3.6.0'),
    'resteasy-jboss-cve-2014-3490': ('org.jboss.resteasy:resteasy-jaxb-provider', '3.0.8.Final'),
    'ssti_thymeleaf_spel_sandbox': ('org.thymeleaf:thymeleaf-spring6', '3.1.4.RELEASE'),
}
# A2 composer: case_id -> (pkg, version)
COMPOSER = {
    'deser_yii2_behavior_typecheck': ('yiisoft/yii2', '2.0.50'),
    'knp-snappy-cve-2023-41330': ('knplabs/knp-snappy', '1.4.2'),
    'xxe_phpspreadsheet_ucs4': ('phpoffice/phpspreadsheet', '1.29.2'),
    'xxe_phpspreadsheet_utf7': ('phpoffice/phpspreadsheet', '1.5.1'),
}
# A3 wordpress plugin zip: case_id -> url
WP = {
    'admin-and-site-enhancements-ase-wordpress-plugin-cve-2026-12083':
        'https://downloads.wordpress.org/plugin/admin-site-enhancements.7.6.3.zip',
    'eazydocs-wordpress-plugin-cve-2024-0248':
        'https://downloads.wordpress.org/plugin/eazydocs.2.3.9.zip',
    'js-help-desk-wordpress-plugin-cve-2023-7337':
        'https://downloads.wordpress.org/plugin/js-support-ticket.2.8.2.zip',
    'wordpress-wp-super-cache-plugin-cve-2013-2011':
        'https://downloads.wordpress.org/plugin/wp-super-cache.1.3.1.zip',
}
# A4 direct tar: case_id -> url
TAR = {
    'majordomo-2-cve-2011-0063':
        'https://ftp.mj2.org/pub/mj2/snapshots/2011-02/majordomo-20110203.tar.gz',
}

def set_entry(cid, stype, vloc, plan):
    e = m[cid]
    e['source_type'] = stype
    e['fetch_plan'] = plan
    for ver in ('v0', 'v1', 'v2'):
        if ver in vloc:
            e[ver]['source_type'] = stype
            e[ver]['sub_type'] = stype
            e[ver]['locator'] = vloc[ver]

n = 0
for cid, (gav, ver) in MAVEN.items():
    if cid not in m:
        print('MISSING', cid); continue
    set_entry(cid, 'maven',
              {v: {'gav': gav, 'version': ver} for v in ('v0', 'v1', 'v2')}, 'maven_sources')
    n += 1
for cid, (pkg, ver) in COMPOSER.items():
    set_entry(cid, 'composer',
              {v: {'pkg': pkg, 'version': ver} for v in ('v0', 'v1', 'v2')}, 'composer_dist')
    n += 1
for cid, url in WP.items():
    set_entry(cid, 'wordpress_plugin_zip',
              {v: {'url': url} for v in ('v0', 'v1', 'v2')}, 'wp_zip')
    n += 1
for cid, url in TAR.items():
    set_entry(cid, 'url_tgz',
              {v: {'url': url} for v in ('v0', 'v1', 'v2')}, 'url_tar')
    n += 1
json.dump(m, open(MF, 'w'), ensure_ascii=False, indent=1)
print(f'backfilled A1-A4: {n} entries')
from collections import Counter
c = Counter(e['source_type'] for e in m.values())
print('new distribution:', dict(c))
