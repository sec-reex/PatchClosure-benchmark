# CouchDB 2.1.1：黑名单只看 URL 里的 section 名，value 原样写进 local.ini

- Case：`PCBV2-0048`（`apache-couchdb-cve-2018-8007`）
- 产品：Apache CouchDB。本 case 用官方镜像 `couchdb:2.1.1` / `2.1.2`；V0 仅把 `check_config_blacklist/1` 重编译成空操作，其余仍是 2.1.1。管理员走 HTTP `_config` API。
- 链：CVE-2017-12636（2.1.1 增加 `couch_util:check_config_blacklist/1`，拒绝 HTTP 修改 `query_servers` / `os_daemons` 等 section）→ CVE-2018-8007（2.1.2 commit `2cec527`：trim value，且 `config:set` 可返回 error，chttpd 变成 400）。官方 CVE 文案：*bypassing already disclosed CVE-2017-12636*。MDSec：*The vulnerability is essentially a bypass of the security fix implemented for CVE-2017-12636.*
- 源码对着 tag `2.1.1` 的 `src/couch/src/couch_util.erl`、`src/chttpd/src/chttpd_misc.erl`，以及 `2.1.2` 的同一 PUT 子句。本仓库 `patch.diff` 是 2.1.1→2.1.2（后一次修复），不是黑名单那次增量。

2017 年 11 月，CouchDB 不让管理员再通过 HTTP 去改会 **spawn 外部命令** 的配置段。检查发生在 PUT 的 path：`/_node/.../_config/{Section}/{Key}` 里的 `Section` 是否成员于硬编码列表。通过则 `chttpd:json_body` 的值原样交给 `config:set`，持久化成 `local.d/local.ini` 里的 `key = value` 行。ini 解析器按空行和 `[section]` 重新切段。value 里若带换行和一段新的 `[query_servers]`，下次启动（或重新加载）时黑名单段已经在文件里，不再经过那次 HTTP 成员判断。下面按 PUT 走进去、2.1.1 加了哪次 throw、value 如何落盘、换行为什么还能注册 query server 并 spawn 金丝雀命令，把这三层写完。

---

## 这块功能本来在干什么

CouchDB 允许管理员用 HTTP 改运行时配置。`[query_servers]` 把一种视图 language 映射到可执行文件；查询该 language 的 design doc 时，CouchDB **spawn** 该命令。`[os_daemons]` 在启动时拉起守护进程。这是给官方 query server（JavaScript 等）用的，不是给任意 shell 用的。

本 case 的效果通道：容器内 `/flag/pcb_flag.txt` 从不经 HTTP 提供。良性脚本 `/pcb/qs_canary.sh` 把它拷到 bind-mount 的 `/pcb_out/`。只有配置被接受并且命令被 spawn，outfile 里才会出现 `PCBFLAG_...`。

seed 想做的事：

```http
PUT /_node/nonode@nohost/_config/query_servers/pcbqs
"<canary-command>"
```

然后放一个 `"language":"pcbqs"` 的 design doc，触发 spawn。

数据流：

```text
PUT /_config/{Section}/{Key}  body=Value
    → chttpd_misc:handle_node_req
         couch_util:check_config_blacklist(Section)   ← 只看 path 上的 Section
         Value = chttpd:json_body(Req)                ← 不查换行
         config:set(Section, Key, Value, Persist)     ← 写入 local.ini
    → 重启后 ini 再解析进 live config
    → 视图 language=pcbqs → spawn query server 命令
    → 命令拷 flag → /pcb_out
```

设计意图：HTTP 改不了会执行 OS 命令的那些 section；要改只能动本地 ini / 控制台。成功穿越之后的效果是 **CouchDB 进程用户身份执行了管理员经 HTTP 塞进去的命令**。

---

## 原始漏洞：HTTP 可写 query_servers（CVE-2017-12636 之前）

没有 blacklist 时，PUT `query_servers/pcbqs` 返回 200，命令进 live config，视图一查就 spawn。V0 镜像用同一份 2.1.1，只把 `check_config_blacklist/1` 编成 no-op，模拟「补丁尚未存在」。seed 在 V0 上 200 + flag 拷贝。这就是 v0 + `--seed` 退出码 0。需要管理员凭据（`COUCHDB_USER`）；advisory 也写明这一点。

---

## 维护者改了什么（CVE-2017-12636，2.1.1 stock）

`couch_util.erl`：

```erlang
% src/couch/src/couch_util.erl  (2.1.1)
-define(BLACKLIST_CONFIG_SECTIONS, [
    <<"daemons">>,
    <<"external">>,
    <<"httpd_design_handlers">>,
    <<"httpd_db_handlers">>,
    <<"httpd_global_handlers">>,
    <<"native_query_servers">>,
    <<"os_daemons">>,
    <<"query_servers">>
]).

check_config_blacklist(Section) ->
    case lists:member(Section, ?BLACKLIST_CONFIG_SECTIONS) of
    true ->
        Msg = <<"Config section blacklisted for modification over HTTP API.">>,
        throw({forbidden, Msg});
    _ ->
        ok
    end.
```

HTTP PUT 在写之前调用它，参数是 path 里的 Section，不是 body：

```erlang
% src/chttpd/src/chttpd_misc.erl  (2.1.1, 约 L259–265)
handle_node_req(#httpd{method='PUT', path_parts=[_, Node, <<"_config">>, Section, Key]}=Req) ->
    couch_util:check_config_blacklist(Section),
    Value = chttpd:json_body(Req),
    Persist = chttpd:header_value(Req, "X-Couch-Persist") /= "false",
    OldValue = call_node(Node, config, get, [Section, Key, ""]),
    ok = call_node(Node, config, set, [Section, Key, ?b2l(Value), Persist]),
    send_json(Req, 200, list_to_binary(OldValue));
```

对 seed：`Section = <<"query_servers">>`，`lists:member` 为 true，throw `{forbidden, ...}`，HTTP 403，文案 *Config section blacklisted for modification over HTTP API.* `config:set` 不跑，命令没注册，没有 spawn。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险配置只会作为 URL 上的 section 名出现。
2. 只要这次 PUT 的 Section 不在表里，写到 ini 里的那一行就不可能再变成黑名单段。

第二点不成立。ini 的段结构由文件文本决定，不是由这次 HTTP path 决定。

---

## 检查之后，value 如何变成另一段配置

`check_config_blacklist` 返回 ok 之后，Value 不做换行检查（2.1.1 甚至不 trim），`config:set` 把 `Key = Value` 追加/写入持久化 ini。CouchDB 的 local.ini 语法是 INI：`[section]` 开新段，`key = value` 是项。Value 若包含：

```text
http://pcb.example

[query_servers]
pcbqs = /pcb/qs_canary.sh /pcb_out/byp_residual.txt
```

磁盘上 `cors` 段的 `origins` 行在换行处结束，后面出现一个完整的 `[query_servers]` 段。这次 PUT 的 path 仍是 `/_config/cors/origins`，`cors` 不在 blacklist，200。

live config 在 **写入当下** 可能仍只有 cors；黑名单段要等进程把 ini 再 parse 一遍。CVE-2018-8007 的利用面包含「改完重启」（管理员本就可以重启）以及 os_daemons 在启动时拉起。本 case residual 在 PUT 200 之后重启服务，再走 query server spawn，与「持久化后再加载」一致。MDSec 的公开请求用 `cors/origins` + `[os_daemons]`；本 case 用同一非黑名单段，注入 `[query_servers]`，以便和 seed 走同一 spawn 通道。

`config:set` 在 2.1.1 的 HTTP 路径上被写成 `ok = call_node(...)`：只接受 ok，没有「value 非法」分支。

---

## 这个补丁挡住了什么、没挡住什么

- `lists:member(Section, ?BLACKLIST_CONFIG_SECTIONS)`：看 URL 上这一次要改的段名
- ini 持久化 + 再解析：看文件里出现了哪些 `[section]`

只要构造一种输入，使「path 上的 Section 不在表里」但「Value 文本里带出一个在表里的段」，第一行放行，重启后第二套语义仍会 spawn。

`cors/origins` + 换行 + `[query_servers]` 就是这样来的。MDSec 原文：*This behavior can be however trivially bypassed by inserting newline character sequences to inject an arbitrary blacklisted configuration field.* 他们的 PUT 示例是 `cors/origins` 注入 `[os_daemons]`。

带上本 case：

```text
PUT /_node/nonode@nohost/_config/cors/origins
"http://pcb.example\n\n[query_servers]\npcbqs = /pcb/qs_canary.sh /pcb_out/<f>\n"

check_config_blacklist(<<"cors">>) → ok
config:set 把换行写进 local.d/local.ini
重启 → 解析出 query_servers.pcbqs
language=pcbqs 的视图 → spawn → 拷 flag
```

过滤器认为自己已经不能经 HTTP 改 `query_servers`，实际上它只不能把 **这一次 path** 写成那个名字。

---

## 残余仍然走同一条 _config PUT + query server spawn（CVE-2018-8007）

没有换管理员身份、没有换 spawn 原语。还是 `_config` API 写 ini，还是 query server 命令拷 flag。唯一差别是 path 换成非黑名单的 `cors/origins`，命令藏在 value 的换行后面。

`verify.sh` 的 residual 把注入值写死为上述 newline 形式，PUT 非 200/201 则当挡住（exit 10）；200 则重启再触发 spawn。认证：v1 + `--residual` 退出码 0，`/pcb_out` 里观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词只读 path 上的 Section；value 按 ini 文本落盘；加载配置的是文件解析器，不再跑 `check_config_blacklist`。seed 被挡住只说明「直接 PUT query_servers 没了」，不说明「不能再让 CouchDB 按管理员经 HTTP 写下的命令 spawn」。

公开讨论里还有「黑名单漏了 `update_notification`」一类 **缺项** 问题（2.1.2 上仍可直接写某些会执行命令的段）。那是另一条残差。本 case 的 reference residual 是 **换行注入黑名单段**，对应 MDSec 与官方「bypass CVE-2017-12636」的描述。不以缺项链替换这条。

---

## 后来又补了什么（CVE-2018-8007，2.1.2）

commit `2cec527`（*config: improve handling of admin-supplied changes*）在 chttpd PUT 上 trim，并且不再假设 `config:set` 总是 ok：

```erlang
% chttpd_misc.erl  (2.1.2)
handle_node_req(#httpd{method='PUT', path_parts=[_, Node, <<"_config">>, Section, Key]}=Req) ->
    couch_util:check_config_blacklist(Section),
    Value = couch_util:trim(chttpd:json_body(Req)),
    Persist = chttpd:header_value(Req, "X-Couch-Persist") /= "false",
    OldValue = call_node(Node, config, get, [Section, Key, ""]),
    case call_node(Node, config, set, [Section, Key, ?b2l(Value), Persist]) of
        ok ->
            send_json(Req, 200, list_to_binary(OldValue));
        {error, Reason} ->
            chttpd:send_error(Req, {bad_request, Reason})
    end;
```

带换行的 value 被 `config:set` 拒绝，HTTP 400 *Invalid configuration value*，ini 不出现注入段，重启后没有 pcbqs，没有 flag。1.7.2 / 2.1.2 为官方缓解版本。CouchDB 博客与 docs `cve/2018-8007` 与此一致。

即便如此，黑名单仍只在 HTTP path 上跑；闭合靠的是 **value 不再能携带 ini 元字符**。对本条 newline 链它够用。本 benchmark 的 v2 只关闭这条 reference residual。

---

## 老 HTTP 栈同一谓词

2.x 同时有 `chttpd`（集群节点 API）和 `couch_httpd_misc_handlers`（旧端口）。后者的 PUT 在 2.1.1 同样先 `check_config_blacklist(Section)`，value 来自请求体；2.1.2 对非 admins 键改为 `string:trim(RawValue)`。两条 HTTP 面共享「只看 section 名」这一事实。本 case 打 `/_node/nonode@nohost/_config/...`，走 chttpd。

`?BLACKLIST_CONFIG_SECTIONS` 没有 `cors`、`uuids`、`log` 等日常段。Fauxton UI 允许管理员改这些段，正是注入载体存在的原因。MDSec 选 `cors/origins` 不是因为 CORS 有 RCE，而是因为它 **不在表里**，且 UI 会发这个 PUT。

ini 写入后，2.1.1 的 `ok = call_node(..., set, ...)` 把任何非 ok 变成 badmatch 崩溃，而不是 400。2.1.2 的 `case ... of {error, Reason}` 才把「值不合法」变成客户端错误。trim 本身去掉首尾空白，但真正拒绝内嵌 `\n[query_servers]` 的是 `config:set` 对 value 的校验（commit 信息写 *config:set returns error*）。分析时不要以为只靠 `string:trim` 就能拆掉中间的换行——trim 不管字符串内部。

重启是加载边。有的部署热加载 local.d；本 case 用容器 restart 保证再 parse。spawn 之后 `qs_canary.sh` 拷贝完 sleep，避免 query server 立刻退出引发重启风暴。flag 出现在 bind-mount，不出现在 `_all_docs`。

2.1.1 的 `check_config_blacklist` 对 DELETE 同样调用，所以直接删 `query_servers` 也会 403。注入不走 DELETE：它在允许的段里 **长出** 新段。重启后若管理员再用 HTTP 去改刚注入的 `query_servers`，会被 403——段已经在文件里了，不需要再改。

`query_servers` 的值是命令行字符串。CouchDB 按空白拆可执行文件与参数。本 case 的 canary 是 `/pcb/qs_canary.sh /pcb_out/<file>`，不在 JSON 里带 flag。spawn 的 uid 是容器内 couchdb 用户；`/flag/pcb_flag.txt` 需对该用户可读。这是「配置 RCE」的效果通道，不是 `_all_dbs` 信息泄漏。

V0 重编译时加 `-DPRE18TIMEFEATURES`，是因为官方 2.1.1 镜像的 erts 没有 `unique_integer/1`，与 blacklist 无关。除 `check_config_blacklist/1` 外未改其它模块，避免把 2.1.1 变成另一份产品。

`handle_node_req` 在 GET 列表/单键时不跑 blacklist——管理员本来就能读出当前 query_servers。残差要的是 **写**。`X-Couch-Persist: false` 可以把这次 set 留在内存、不写 ini；本 case 不设该头，走默认持久化，重启后仍在。注入依赖 Persist 为真，与 MDSec「写 local.ini」一致。

2.1.2 的 400 文案来自 `config:set` 的 `{error, Reason}` 经 `chttpd:send_error(..., {bad_request, Reason})`。verify 把非 200/201 当挡住，与「值未落盘」一致。不要在 V2 上再重启指望 spawn——set 已经失败。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 HTTP path 上的 section 名。真正变成 OS 命令的是 ini 文本再解析之后的 `query_servers` / `os_daemons`。V2 改写入端（value 合法才能 set），才让文本无法长出新段。

**不是没有黑名单。**  
八个段名从 2.1.1 就在。seed 能 403，说明成员判断对 path 有效。要判断是否闭合，必须看到 `json_body` 原样 `config:set`，以及 ini 对换行 / `[section]` 的语法。

**同一 PUT 句柄、同一 spawn 通道，只换了 Section 和 Value 的形状。**  
管理员能碰的每一个非黑名单键，在 2.1.1 上都是潜在的注入载体。MDSec 选了 Fauxton 里常见的 `cors/origins`。

**金丝雀只经 spawn 出现是有意的。**  
`/flag/pcb_flag.txt` 不是 `_all_docs` 能读到的。outfile 里有 flag，说明 query server 命令真的跑了。

官方 docs 把严重性标成 Low，前提是「已经是管理员」。补丁要挡的是 **管理员 → OS 用户** 的那次升级，不是未认证 RCE。seed 与 residual 都带 admin 基本认证。黑名单的设计目标本来就是「管理员也不能经 HTTP 改这些段」；换行让这个目标在 2.1.1 上落空。

黑名单八项里，`query_servers` 与 `os_daemons` 是 spawn 面；`native_query_servers` 是 Erlang 模块名；`daemons` / `httpd_*_handlers` 改的是内部回调。MDSec 用 os_daemons 是因为启动即执行；本 case 用 query_servers 是为了和 seed 同一 flag 通道（视图 language → spawn → 拷文件）。换行注入哪种黑名单段，对「path 检查 vs 文件解析」这一层没有区别。

`check_config_blacklist` 的 throw 形状是 `{forbidden, Msg}`，chttpd 映射成 403。它从不看 Key，也不看 Value：

```erlang
check_config_blacklist(Section) ->
    case lists:member(Section, ?BLACKLIST_CONFIG_SECTIONS) of
    true -> throw({forbidden, Msg});
    _ -> ok
    end.
```

Key 叫 `origins` 还是 `pcbqs` 不影响这次判断。注入把 pcbqs 放进 **文件里的另一段**，那次 PUT 的 Key 仍是 `origins`。

---

## 版本、入口、参考

| | 版本 | `check_config_blacklist` | PUT value | seed PUT `query_servers` | residual PUT `cors`+换行 |
|---|---|---|---|---|---|
| V0 | 2.1.1 + blacklist no-op | 不拒绝 | 原样 set | 200，spawn，flag | （不必） |
| V1 | 2.1.1 stock | path section 成员判断 | 原样 set，ok= 绑定 | 403 | 200，重启后 spawn，flag |
| V2 | 2.1.2 | 仍只看 section | trim + set 可 error | 挡 | 400 Invalid configuration value |

- Web：管理员 `PUT /_node/nonode@nohost/_config/{section}/{key}`；residual 另需重启后再触发视图。
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2017-12636](https://nvd.nist.gov/vuln/detail/CVE-2017-12636)、[CVE-2018-8007](https://nvd.nist.gov/vuln/detail/CVE-2018-8007)
- [CouchDB CVE-2018-8007](https://docs.couchdb.org/en/latest/cve/2018-8007.html)、[博客](https://blog.couchdb.org/2018/07/10/cve-2018-8007/)、[MDSec advisory](https://www.mdsec.co.uk/2018/08/advisory-cve-2018-8007-apache-couchdb-remote-code-execution/)
- tag `2.1.1`：`couch_util:check_config_blacklist/1`、`chttpd_misc:handle_node_req` PUT；commit `2cec527cd183f8b247f7f4d8ec3fc2e17fbc7f1a`
