# apache-solr-cve-2013-6408

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Apache Solr XML External Entity injection (XXE, CWE-611) — genuine **incomplete fix**.
**Run mode: real running Solr server, XXE triggered by EXTERNAL HTTP POST** (not in-process).

- **CVE-2013-6407** (SOLR-3895, fixed 4.1.0): XXE in the XML `UpdateRequestHandler` (`XMLLoader`);
  fixed by `EmptyEntityResolver.configureXMLInputFactory` on its `XMLInputFactory`.
- **CVE-2013-6408** (SOLR-4881, fixed 4.3.1): the SAME guard was *"overlooked while committing
  SOLR-3895"* for a second handler, `DocumentAnalysisRequestHandler`, whose own `XMLInputFactory`
  kept resolving external entities. NVD: *"this vulnerability exists because of an incomplete fix
  for CVE-2013-6407."*

Versions (real Apache Solr binary dists from archive.apache.org, bundled Jetty + example
`collection1` core): V0 = 4.0.0 (port 18980) · V1 (target) = 4.1.0 (port 18981) · V2 = 4.3.1 (port 18982).
Each service boots the REAL server (`java -jar start.jar`) and publishes 8983. The stock
`solrconfig.xml` registers both `/update` and `/analysis/document`. Canary = read-exfil: `${PCB_FLAG}`
is planted at `/flag` (outside the app dir); an external HTTP POST of `<!ENTITY xxe SYSTEM
"file:///flag">` surfaces the token in the real Solr HTTP response.

Differential (external HTTP POST):
| version | original -> `/update` (XMLLoader) | residual -> `/analysis/document` (DocumentAnalysisRequestHandler) |
|---|---|---|
| V0 4.0.0 | REACHES (flag in int-parse error) | (reaches) |
| V1 4.1.0 | BLOCKED | **REACHES** (flag in field analysis) <- incomplete fix |
| V2 4.3.1 | (blocked) | BLOCKED |

Gate: `python3 oracle.py --run-gate --with-v2` -> passed=true (see `repro.log`).

Note: stale files from the previous (banned) in-process reflection build remain in this dir and are
NOT referenced by the current recipe: `Driver.java`, `pom.xml`. See repro.log.
