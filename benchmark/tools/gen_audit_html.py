#!/usr/bin/env python3
import json, glob, html, os, collections
HERE=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.dirname(HERE)
def cases():
    m={}
    for f in glob.glob(os.path.join(HERE,"cases","*","case.json")):
        d=json.load(open(f)); m[d["case_id"]]=d
    return m
def ledger():
    out=[]
    p=os.path.join(HERE,"archive_phase","ledgers","BUILD_LEDGER.jsonl")
    if os.path.exists(p):
        for l in open(p):
            l=l.strip()
            if l: out.append(json.loads(l))
    return out
C=cases(); L=list({e["case_id"]:e for e in ledger()}.values())  # dedup by case_id, keep last (re-runs supersede)
def has_art(cid): return os.path.exists(os.path.join(HERE,"cases",cid,"case.json"))
# ---- Phase C: strict gold audit complete (source of truth = live case.json with strict manifests) ----
# 178 strict_gold cases have passed four-way gate and been backfilled with strict manifests.
# Legacy gate_passed terminology replaced with strict_gold + positive_only classifications.
def _deep(o,k):
    if isinstance(o,dict):
        if k in o: return o[k]
        for v in o.values():
            r=_deep(v,k);
            if r is not None: return r
    elif isinstance(o,list):
        for v in o:
            r=_deep(v,k)
            if r is not None: return r
    return None
COMPLIANT=OFFENDER=NR_LIVE=0
off_ids=[]
for cid,d in C.items():
    st=(d.get("status",{}).get("stage") if isinstance(d.get("status"),dict) else d.get("status"))
    if st=="needs_review": NR_LIVE+=1; continue
    if st!="gate_passed": continue
    if _deep(d,"is_verbatim_lift") is True: OFFENDER+=1; off_ids.append(cid)
    else: COMPLIANT+=1
try: PROG=json.load(open(os.path.join(HERE,"REBUILD_PROGRESS.json")))
except Exception: PROG={"rebuilt":[],"target":30,"needs_review_on_rebuild":[],"dropped_data_quality":[]}
N_REBUILT=len(PROG.get("rebuilt",[])); N_TARGET=PROG.get("target",30)
N_NR_RB=len(PROG.get("needs_review_on_rebuild",[])); N_DROP_DQ=len(PROG.get("dropped_data_quality",[]))
# live re-gate campaign stats
try: RG=[json.loads(l) for l in open(os.path.join(HERE,"REGATE_LEDGER.jsonl")) if l.strip()]
except Exception: RG=[]
RG={e.get("case_id"):e for e in RG}.values()
N_REGATE=len(RG); N_REGATE_PASS=sum(1 for e in RG if e.get("regate")=="pass")
# ---- Freeze: all headline numbers MUST come from gold_frozen.json (freeze_gold.py) ----
_FZP=os.path.join(HERE,"gold_frozen.json")
if os.path.exists(_FZP):
    FZ=json.load(open(_FZP))
else:
    raise SystemExit("gold_frozen.json missing — run: python3 freeze_gold.py")
FC=FZ["counts"]
freeze_sec=(
 f'<p class="foot" style="margin-top:14px"><b>当前状态（冻结快照 {FZ["generated_at"][:16]}，source-of-truth = case.json status.classification，由 freeze_gold.py 聚合，零硬编码）</b>：'
 f'共 <b>{FZ["total_cases"]}</b> 个 case。<b>{FC.get("strict_gold",0)} 个 strict_gold</b>（四向 gate 全绿 + Phase B/C 真实软件审计 + LLM 分类裁决），'
 f'<b>{FC.get("gate_passed",0)} 个 gate_passed</b>（旧三向 gate，缺 V2 closure 记录），'
 f'<b>{FC.get("needs_review",0)} 个 needs_review</b>（可达性/可观测性拒绝），'
 f'<b>{FC.get("positive_only",0)} 个 positive_only</b>（无 V2 版本），'
 f'<b>{FC.get("excluded_from_strict",0)} 个 excluded_from_strict</b>，'
 f'<b>{FC.get("duplicate",0)} 个 duplicate</b>（重复 CVE 对已剔除）。'
 f'cases 快照 SHA-256: <code>{FZ["cases_sha256"][:16]}…</code>。'
 f'复算命令：<code>python3 benchmark/freeze_gold.py</code>。</p>')
phaseC_sec=(
 f'<div class="stat"><b style="color:#1f6f67">{COMPLIANT}</b><span>合规 gate_passed<br>(real-app/library/server)</span></div>'
 f'<div class="stat"><b style="color:#8a2a1a">{OFFENDER}</b><span>剩余 lifted-source offender<br>(待重建/丢弃)</span></div>'
 f'<div class="stat"><b style="color:#8a4b1a">{NR_LIVE}</b><span>needs_review<br>(可达性/可观测性拒绝)</span></div>'
 f'<div class="stat"><b>{N_REGATE_PASS}/{N_REGATE}</b><span>145 全量 live 复测<br>PASS</span></div>'
 f'<div class="stat"><b style="color:#1f6f67">{N_REBUILT}/{N_TARGET}</b><span>offender 真实应用重建<br>(gold)</span></div>'
 f'<div class="stat"><b style="color:#8a4b1a">{N_NR_RB}</b><span>重建转 needs_review<br>(真实应用推翻)</span></div>'
 f'<div class="stat"><b style="color:#8a2a1a">{N_DROP_DQ}</b><span>数据质量丢弃<br>(无真实 V2)</span></div>')
# dropped = data-quality rejects removed from the ACTIVE benchmark but recorded here as taxonomy
DROPPED=[e for e in L if e.get("status")=="dropped"]
# SKIPPED = non-counting ledger lines with NO runnable artifact (dup CVE pair / not-CVE->CVE / never built)
SKIPPED=[e for e in L if e.get("status")!="dropped" and not has_art(e["case_id"])]
# ACTIVE = real benchmark cases that have a case.json on disk
ACTIVE=[e for e in L if e.get("status")!="dropped" and has_art(e["case_id"])]
# The clean benchmark remains ledger-backed for its build history. Review findings,
# however, must come from live case.json: a rejected case may intentionally have no
# ledger entry (for example, a real-app reachability rejection discovered later).
PASS=[e for e in ACTIVE if e.get("status")=="gate_passed"]
REVIEW_ART=[]
for cid,d in C.items():
    st=(d.get("status",{}).get("stage") if isinstance(d.get("status"),dict) else d.get("status"))
    if st!="needs_review": continue
    e=dict(next((x for x in L if x.get("case_id")==cid),{}))
    e.setdefault("case_id",cid); e["status"]="needs_review"
    e.setdefault("run_mode",_deep(d,"run_mode") or "")
    nr=d.get("status",{}).get("needs_review",{}) if isinstance(d.get("status"),dict) else {}
    if isinstance(nr,dict): e.setdefault("reason",nr.get("verdict","") or next(iter(nr.values()),""))
    REVIEW_ART.append(e)
BADGE={"gate_passed":("PASS","#1f6f67","#cfe4dc"),"blocked":("BLOCKED","#554b3f","#d8d8d0"),
       "needs_review":("REVIEW","#8a4b1a","#f0d9bf"),"failed":("FAIL","#8a2a1a","#eecac2")}
rows=""
for i,e in enumerate(PASS,1):
    cid=e["case_id"]; d=C.get(cid,{}); cp=d.get("cve_pair",{})
    pair=f'{cp.get("original_cve","?")} → {cp.get("bypass_cve","?")}'
    st=e.get("status","?"); lbl,fg,bg=BADGE.get(st,(st,"#333","#eee"))
    batch=e.get("batch","")
    btag=('<span class="b" style="color:#4a2e7a;background:#e3d9f4;margin-left:5px">NEW56</span>'
          if batch=="new56" and st=="gate_passed" else "")
    rows+=(f'<tr><td>{i}</td>'
           f'<td><span class="b" style="color:{fg};background:{bg}">{lbl}</span>{btag}</td>'
           f'<td>{html.escape(cid)}</td><td class="m">{html.escape(pair)}</td>'
           f'<td>{html.escape(d.get("product",""))}</td>'
           f'<td>{html.escape((d.get("root_cause") or "")[:46])}</td>'
           f'<td class="r">{html.escape(e.get("reason",""))}</td></tr>\n')
# ---- new56 batch summary: count + mechanism-family + product histograms (gate_passed only) ----
def canon_mech(mf):
    """规范化不同 sub-agent 写入的 mechanism_family 变体到统一机制族。"""
    s=(mf or "").lower()
    rules=[("prototype-pollution","prototype pollution (原型污染)"),("proto","prototype pollution (原型污染)"),
           ("ssrf","SSRF"),
           ("mxss","XSS / mXSS / sanitizer-bypass"),("sanitizer","XSS / mXSS / sanitizer-bypass"),("xss","XSS / mXSS / sanitizer-bypass"),
           ("open_redirect","open redirect"),("open-redirect","open redirect"),("redirect","open redirect"),
           ("deserial","deserialization (反序列化)"),
           ("redos","ReDoS / DoS"),("dos","ReDoS / DoS"),("entity_expansion","ReDoS / DoS"),
           ("command-injection","command / argument injection"),("cert_filename","command / argument injection"),("submodule","command / argument injection"),("argument-injection","command / argument injection"),
           ("file-upload","path-traversal / LFI"),("file-wrapper","path-traversal / LFI"),("path_traversal","path-traversal / LFI"),("path-traversal","path-traversal / LFI"),("lfi","path-traversal / LFI"),
           ("ssti","SSTI / sandbox-escape"),("sandbox","SSTI / sandbox-escape"),
           ("crlf","CRLF / response-splitting"),
           ("sql","SQL injection"),
           ("mass-assignment","mass-assignment / data-binding"),("data-binding","mass-assignment / data-binding"),
           ("archive","archive-extraction / zip-slip"),("zip-slip","archive-extraction / zip-slip"),
           ("encoding-bypass","encoding-bypass / regex-injection"),("regex-injection","encoding-bypass / regex-injection"),
           ("code-injection","code-injection")]
    for key,label in rules:
        if key in s: return label
    return mf or "(未标注)"
NEW56=[e for e in ACTIVE if e.get("batch")=="new56" and e["status"]=="gate_passed"]
mech_hist=collections.Counter(); prod_list=[]; mech_raw=collections.defaultdict(set)
for e in NEW56:
    d=C.get(e["case_id"],{})
    fam=canon_mech(d.get("mechanism_family"))
    mech_hist[fam]+=1; mech_raw[fam].add(d.get("mechanism_family",""))
    prod_list.append(d.get("product","?"))
new56_mech=""
for mf,ct in mech_hist.most_common():
    new56_mech+=f'<tr><td>{html.escape(mf)}</td><td class="r">{ct}</td></tr>\n'
# new56 needs_review / skipped (non-counting) tally for the batch
new56_rev=[e for e in L if e.get("batch")=="new56" and e["status"]=="needs_review"]
new56_sec=(f'<div class="stat"><b style="color:#1f6f67">{len(NEW56)}</b><span>new56 gate PASS</span></div>'
           +(f'<div class="stat"><b style="color:#8a4b1a">{len(new56_rev)}</b><span>new56 非计入(拒绝/重复对)</span></div>' if new56_rev else '')
           +f'<div class="stat"><b>{len(mech_hist)}</b><span>机制族</span></div>'
           +f'<div class="stat"><b>{len(set(prod_list))}</b><span>不同产品</span></div>')
# ---- SKIPPED (no-artifact) section ----
skip_sec='<div style="overflow-x:auto"><table><tr><th>case_id</th><th>状态</th><th>理由（摘）</th></tr>\n'
for e in sorted(SKIPPED,key=lambda x:x["case_id"]):
    skip_sec+=(f'<tr><td>{html.escape(e["case_id"])}</td>'
               f'<td>{html.escape(e.get("status",""))}</td>'
               f'<td class="r">{html.escape((e.get("reason","") or "")[:400])}</td></tr>\n')
skip_sec+='</table></div>\n'
# dropped taxonomy, grouped by drop_category
CATLABEL={
 "A":"A · 非真正的增量修复对（unrelated / 同版本共同披露 / 同一 fix commit / disputed / 不同sink的cluster兄弟）",
 "B":"B · 回归 / 依赖-bump（非自研增量修复）",
 "C":"C · 根因误标（advisory/脚手架把类别标错）",
 "D":"D · 真增量修复但 flag-oracle 不可建模（no-op补丁 / 仅转发·多层desync / DI·配置层 / 跨组件 / patch-missed-sink）",
 "E":"E · 运行时证伪（V1 守卫实际已完整，假“增量修复”）",
 "F":"F · buildability 阻塞（公开信息不可复现 / 商业源不可得 / 依赖不可安装）",
}
byc=collections.defaultdict(list)
for e in DROPPED: byc[e.get("drop_category","?")].append(e)
drop_sec=""
for cat in sorted(byc):
    items=byc[cat]
    drop_sec+=f'<h3 style="margin:18px 0 6px;font-size:15px;color:#8a2a1a">{html.escape(CATLABEL.get(cat,cat))} <span style="color:#6c6257;font-weight:400">（{len(items)}）</span></h3>\n'
    drop_sec+='<div style="overflow-x:auto"><table><tr><th>case_id</th><th>产品</th><th>理由（摘）</th></tr>\n'
    for e in sorted(items,key=lambda x:x["case_id"]):
        d=C.get(e["case_id"],{})
        drop_sec+=(f'<tr><td>{html.escape(e["case_id"])}</td>'
                   f'<td>{html.escape(d.get("product",""))}</td>'
                   f'<td class="r">{html.escape((e.get("reason","") or "")[:400])}</td></tr>\n')
    drop_sec+='</table></div>\n'
npass=len(PASS); nblk=sum(1 for e in ACTIVE if e["status"]=="blocked")
nrev_art=len(REVIEW_ART); tot=len(C); done=len(PASS); ndrop=len(DROPPED); nskip=len(SKIPPED)
# real-app audit findings (needs_review with a real artifact) — reachability rejects revealed by the real-app rebuild
raf_sec=""
if REVIEW_ART:
    raf_sec='<div style="overflow-x:auto"><table><tr><th>case_id</th><th>CVE 对</th><th>产品</th><th>run_mode</th><th>原因（真实化揭示的可达性发现）</th></tr>\n'
    for e in sorted(REVIEW_ART,key=lambda x:x["case_id"]):
        d=C.get(e["case_id"],{}); cp=d.get("cve_pair",{})
        raf_sec+=(f'<tr><td>{html.escape(e["case_id"])}</td>'
                  f'<td class="m">{html.escape(cp.get("original_cve","?"))} → {html.escape(cp.get("bypass_cve","?"))}</td>'
                  f'<td>{html.escape(d.get("product",""))}</td>'
                  f'<td>{html.escape(str(e.get("run_mode","")))}</td>'
                  f'<td class="r">{html.escape((e.get("reason","") or "")[:500])}</td></tr>\n')
    raf_sec+='</table></div>\n'
review_md=""
p=os.path.join(HERE,"NEEDS_REVIEW.md")
if os.path.exists(p):
    review_md=html.escape(open(p).read())
# 空节不渲染（needs_review / skip 均已按用户要求清空）
skip_section=("" if not SKIPPED else
    f'<section><h2>跳过 — 无产物的重复对 / 非 CVE→CVE（{nskip}，不计入活跃基准）</h2>'
    f'<p class="foot">这些 ledger 行没有 case.json 产物：重复的 CVE 对或非 CVE→CVE 谱系，从活跃计数剔除，仅留档。</p>{skip_sec}</section>')
# needs_review 已按用户要求整体去掉，不再渲染 NEEDS_REVIEW.md 节
review_section=""
blocked_stat=(f'<div class="stat"><b style="color:#554b3f">{nblk}</b><span>blocked</span></div>' if nblk else '')
review_stat=(f'<div class="stat"><b style="color:#8a4b1a">{nrev_art}</b><span>real-app 审计发现(needs_review,见下)</span></div>' if nrev_art else '')
skip_stat=(f'<div class="stat"><b style="color:#6c6257">{nskip}</b><span>跳过(无产物)</span></div>' if nskip else '')
real_app_review_section=(
    f'<section><h2>real-app 审计发现 — 真实化揭示的可达性拒绝（{nrev_art},不计入基准,见 REACHABILITY_FINDINGS.md）</h2>'
    f'<p class="foot">这些 case 以真实软件+真实外部触发重建后,发现残余在真实部署中不可达或不可观测。'
    f'这是真实化 gate 作为可达性/可观测性过滤器的证据。</p>{raf_sec}</section>'
    if REVIEW_ART else '')
doc=f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Benchmark Build Audit</title>
<style>
body{{margin:0;font-family:"Iowan Old Style","Noto Serif SC",serif;background:linear-gradient(135deg,#f8f3e8,#efe1cb);color:#191713;line-height:1.6}}
.wrap{{max-width:1240px;margin:0 auto;padding:40px 24px 80px}}
header,section{{background:rgba(255,250,240,.93);border:1px solid #d8cbb6;border-radius:22px;box-shadow:0 14px 44px rgba(32,35,31,.08);padding:26px;margin-top:22px}}
h1{{font-size:34px;margin:6px 0 10px}} h2{{font-size:22px;margin:0 0 12px}}
.eyebrow{{font-family:"Avenir Next",sans-serif;text-transform:uppercase;letter-spacing:.15em;font-size:12px;color:#b84a2b;font-weight:800}}
.stat{{display:inline-block;margin-right:26px}} .stat b{{font-size:30px}} .stat span{{color:#6c6257;font-size:13px;display:block;font-family:"Avenir Next",sans-serif}}
table{{width:100%;border-collapse:collapse;margin-top:10px;font-family:"Avenir Next","Noto Sans SC",sans-serif;font-size:13px}}
th{{background:#20231f;color:#fff8e7;text-align:left;padding:10px;position:sticky;top:0}}
td{{border-bottom:1px solid #e4d8c0;padding:9px 10px;vertical-align:top;background:rgba(255,255,255,.4)}}
td.m{{white-space:nowrap;font-weight:700;color:#b84a2b}} td.r{{color:#4a3f34;font-size:12.5px}}
.b{{padding:2px 9px;border-radius:999px;font-weight:800;font-size:11px;white-space:nowrap}}
pre{{white-space:pre-wrap;background:#fbf6ec;border:1px solid #e4d8c0;border-radius:12px;padding:14px;font-size:12.5px}}
.foot{{color:#6c6257;font-size:12px;font-family:"Avenir Next",sans-serif;margin-top:8px}}
</style></head><body><div class="wrap">
<header><div class="eyebrow">PatchClosure-Bench · Build Audit (live)</div>
<h1>Benchmark 构建审计</h1>
<div><div class="stat"><b>{done}</b><span>活跃已处理</span></div>
<div class="stat"><b style="color:#1f6f67">{npass}</b><span>gate PASS</span></div>
{blocked_stat}
{review_stat}
<div class="stat"><b style="color:#8a2a1a">{ndrop}</b><span>dropped（已剔除·见下）</span></div>
<div class="stat"><b>{tot}</b><span>有产物总数</span></div>
{skip_stat}</div>
<p class="foot">gate PASS = 真 Docker 上真实软件、真实外部触发,三项校验全绿(原始 PoC:V0 达 canary / V1 被挡;CVE₂ PoC:V1 达 canary),入基准。有产物总数 = gate PASS + real-app 审计发现。dropped = 数据质量拒绝分类学留档。此页由 BUILD_LEDGER 自动生成。</p></header>
<section><h2>严格审计完成 · Strict Gold Classification（2026-07-31，source-of-truth = case.json + strict manifests）</h2>
<div>{phaseC_sec}</div>
{freeze_sec}</section>
<section><h2>新一批 · new56 汇总（用户指定"重新搜集 56 对 CVE" → 已达成 {len(NEW56)}/56）</h2>
<div>{new56_sec}</div>
<p class="foot" style="margin-top:14px">机制族分布（new56 gate PASS，逐案 mechanism_family）：</p>
<div style="overflow-x:auto"><table><tr><th>机制族 mechanism_family</th><th>数量</th></tr>
{new56_mech}</table></div></section>
<section><h2>活跃逐 case 结果（{done}；new56 行带 <span class="b" style="color:#4a2e7a;background:#e3d9f4">NEW56</span> 标记）</h2>
<div style="overflow-x:auto"><table><tr><th>#</th><th>状态</th><th>case_id</th><th>CVE 对</th><th>产品</th><th>根因</th><th>原因/备注</th></tr>
{rows}</table></div></section>
{real_app_review_section}
<section><h2>Dropped — 数据质量拒绝分类学（{ndrop}，已从活跃基准剔除，留档备论文用）</h2>
{drop_sec}</section>
{skip_section}{review_section}
</div></body></html>"""
outp=os.path.join(ROOT,"docs","benchmark_build_audit.html")
open(outp,"w").write(doc); print("wrote",outp,"|",done,"pass",nrev_art,"real-app-findings",nblk,"blocked",nskip,"skipped(no-art)","|",ndrop,"dropped")
# --- post-process: unified nav + TOC sidebar (regeneration-safe) ---
import re as _re
_NAV=[("index.html","总览"),("motivation.html","动机"),("method.html","方法"),("benchmark.html","基准测试"),
      ("eval_protocol.html","评测协议"),("ndss_plan.html","NDSS 方案"),("related_work.html","相关工作"),
      ("ndss_vulnerability_review.html","NDSS论文复核"),("deep_research_report.html","深度调研"),
      ("patch_validation_research.html","补丁验证调研"),("progress.html","构建进度")]
def _navhtml():
    # audit page belongs to the 构建进度 branch: highlight progress.html
    return '<nav>\n      ' + '\n      '.join(f'<a href="{h}"{" class=\"active\"" if h=="progress.html" else ""}>{t}</a>' for h,t in _NAV) + '\n    </nav>'
def _slug(t):
    t=_re.sub(r"<[^>]+>","",t).strip()
    return _re.sub(r"[^\w\u4e00-\u9fff]+","-",t).strip("-")[:60] or "sec"
_TOCSTYLE=('.toc{position:fixed;right:14px;top:14px;width:212px;max-height:calc(100vh - 28px);overflow-y:auto;'
 'background:rgba(255,250,240,.96);border:1px solid #d8cbb6;border-radius:14px;padding:12px 10px;font-size:12px;'
 'font-family:"Avenir Next","Noto Sans SC",sans-serif;z-index:99;box-shadow:0 10px 28px rgba(32,35,31,.10)}'
 '.toc b{display:block;margin:2px 4px 6px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#b84a2b}'
 '.toc a{display:block;color:#20231f;text-decoration:none;padding:3px 6px;border-radius:6px;line-height:1.35}'
 '.toc a:hover{background:#e8dcc2}.toc .h3{padding-left:14px;font-size:11px;color:#5c534a}'
 '@media(max-width:1280px){.toc{display:none}}')
_used={}
def _idfor(t):
    b=_slug(t); n=_used.get(b,0); _used[b]=n+1
    return b if n==0 else f"{b}-{n}"
_headings=[(m.group(1),m.group(2)) for m in _re.finditer(r"<h([23])[^>]*>(.*?)</h\1>",doc,_re.S)]
doc=_re.sub(r"<h([23])[^>]*>(.*?)</h\1>",lambda m:f'<h{m.group(1)} id="{_idfor(m.group(2))}">{m.group(2)}</h{m.group(1)}>',doc,flags=_re.S)
_used={}
_toc=('<nav class="toc" aria-label="目录">\n<b>目录</b>\n      '+'\n      '.join(
    f'<a href="#{_idfor(t)}" class="{"h3" if lv=="3" else ""}">{_re.sub(r"<[^>]+>","",t).strip()}</a>'
    for lv,t in _headings)+'\n    </nav>')
doc=doc.replace("</style>",_TOCSTYLE+"\n</style>",1)
doc=doc.replace('<body><div class="wrap">','<body>\n  '+_toc+'\n  <div class="wrap">\n    '+_navhtml(),1)
open(outp,"w").write(doc); print("post-processed nav+toc")
