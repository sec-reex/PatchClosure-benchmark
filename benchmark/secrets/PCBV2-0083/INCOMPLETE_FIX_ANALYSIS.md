# AWStats：剥掉 `..` 之后，绝对路径仍被 rel2abs 打开

- Case：`PCBV2-0083`
- 产品：AWStats（Perl CGI 日志分析；`wwwroot/cgi-bin/awstats.pl`）
- 链：CVE-2017-1000501（7.6 → 7.7，commit `06c0ab29` / `cf219843`）→ CVE-2020-29600（7.7 → 7.8，commit `d4d815d`）
- 源码对着官方 tag `7.7` 的 `wwwroot/cgi-bin/awstats.pl`：CGI 查询串解析末尾的 `$SiteConfig =~ s/\.\.//g`、`Read_Config` 的 `@PossibleConfigDir` 循环和 `File::Spec->rel2abs` 回退。运行时是整份 CGI + Apache，不是抽出来的函数。

2017 年底，AWStats 7.7 给 `config=` 加了一行 `s/\.\.//g`，想挡住目录穿越。2020 年 NVD 把后续问题记成 CVE-2020-29600，并写明 *this issue exists because of an incomplete fix for CVE-2017-1000501*：`config=` 仍接受绝对路径。GitHub issue #90 里报告者用 `config=/etc/passwd` 证明 7.7 仍会打开它。

根因不只是「正则写窄了」。检查插在「`$SiteConfig` 字符串里有没有两个点」这一层；真正 `open` 配置文件的是 `Read_Config` 里另一套拼接和绝对路径回退。下面按请求走进去、7.7 改了哪一行、消毒后怎么变成磁盘路径、rel2abs 为什么不拦，把这几层写完。

---

## 这块功能本来在干什么

AWStats 用 `config=` 选配置档案：通常是站点名，对应 `/etc/awstats/awstats.<site>.conf`。一次典型请求：

```http
GET /cgi-bin/awstats.pl?config=mysite
```

CGI 从 `QUERY_STRING` 取出 `config=`，`Sanitize` 之后放进 `$SiteConfig`，再交给 `Read_Config`。`Read_Config` 在一组目录里找 `awstats.$SiteConfig.conf`、`awstats.conf`，或直接把 `$SiteConfig` 当文件名拼到搜索目录后面。找不到时，7.7 还有一段「把 `$SiteConfig` 当绝对路径 `rel2abs` 再 open」。

设计意图：`config=` 是配置**名字**（`mysite`），文件必须落在 `$DIR` / `/etc/awstats` / `/usr/local/etc/awstats` / `/etc` / `/etc/opt/awstats`。没有登录。成功穿越之后的效果是：**读出搜索目录之外的文件，并按 AWStats 配置语法解析**。本 case 的金丝雀是 `/pcb_canary/flag.conf`，一行 `Include "<FLAG>"`，在 docroot 和所有配置搜索目录之外。解析失败时错误页会把 Include 目标（也就是 FLAG）反射进 HTML。

数据流：

```text
HTTP config=
    → CGI 解析 QueryString
         $SiteConfig = Sanitize(config)
         V1：$SiteConfig =~ s/\.\.//g          ← 补丁插在这里，只改字符串
    → Read_Config($SiteConfig)
         在 @PossibleConfigDir 里找 awstats.$SiteConfig.conf 等
         找不到则 File::Spec->rel2abs($SiteConfig)   ← 真正的 open，不再查 ..
         open CONFIG
    → Parse_Config → Include 失败则错误页带出 FLAG
```

---

## 原始漏洞：`config=` 里的 `../`（CVE-2017-1000501，7.6）

7.6 的 CGI 解析器取出 `$SiteConfig` 之后，直接进 `Read_Config`，中间没有任何 `..` 处理。NVD 写的是 *path traversal flaw in the handling of the "config" and "migrate" parameters*。公开 PoC 用 `config=../../../../etc/passwd` 一类路径。

本 case 的 seed 从真实目录 `/etc` 往上爬到文件系统根，再落到树外金丝雀：

```text
config = /etc/../pcb_canary/flag.conf
```

7.6 没有 `s/\.\.//g`。`Read_Config` 最终打开 `/pcb_canary/flag.conf`，错误页里出现 `PCBFLAG_...`。没有鉴权。

---

## 维护者改了什么（CVE-2017-1000501 修复，7.7）

7.7 只在 CGI 解析块和命令行解析块的**末尾**各加一行，发生在 `Read_Config` **之前**。对着官方 tag `7.7`：

```perl
# wwwroot/cgi-bin/awstats.pl  (AWStats 7.7, CGI 分支末尾，约 L16428–16481)
  if ( $QueryString =~ /config=([^&]+)/i ) {
    $SiteConfig = &Sanitize("$1");
  }
  # ... 其它 query 参数 ...
  $SiteConfig =~ s/\.\.//g;    # Avoid directory transversal
```

命令行分支同样有 `$SiteConfig =~ s/\.\.//g;`（约 L16589）。

V1 正则的字面意思：全局删除子串 `..`（两个点），不要求两侧是斜杠，没有 `while` 重扫，没有「realpath 必须落在 /etc/awstats 下」。

对 seed 这种明文 `/etc/../pcb_canary/flag.conf`，它确实够用：

```text
输入:  /etc/../pcb_canary/flag.conf
V1 后: /etc/pcb_canary/flag.conf
```

`..` 被抠掉，中间的斜杠留下，路径不再解析到 `/pcb_canary/flag.conf`。搜索目录里也没有这个文件，错误页没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险路径段长得像两个连续的点。
2. 删掉 `..` 之后，剩下的字符串不会再指向搜索目录之外的文件。

第二点不成立。更关键的是：这一行之后，代码仍然可能把 `$SiteConfig` 当**已经绝对的路径**打开，而且那次打开**不再做 `..` 检查**。

---

## 消毒之后，路径怎么接到磁盘上

V1 的 `s///` 一结束，主流程调用 `Read_Config`。7.7 的搜索循环和绝对路径回退（约 L1653–1740）：

```perl
# wwwroot/cgi-bin/awstats.pl :: Read_Config  (AWStats 7.7)
sub Read_Config {
  my @PossibleConfigDir = (
    "$DIR",
    "/etc/awstats",
    "/usr/local/etc/awstats", "/etc",
    "/etc/opt/awstats"
  );
  # ...
  foreach (@PossibleConfigDir) {
    my $searchdir = $_;
    if ( $searchdir && $searchdir !~ /[\\\/]$/ ) { $searchdir .= "/"; }
    # 试 $searchdir$PROG.$SiteConfig.conf
    # 试 $searchdir$PROG.conf
    # 试 $searchdir$SiteConfig          ← 把 config= 当相对文件名拼上去
  }

  #CL - Added to open config if full path is passed to awstats
  if ( !$FileConfig ) {
    my $SiteConfigBis = File::Spec->rel2abs($SiteConfig);
    debug("Finally, try to open an absolute path : $SiteConfigBis", 2);
    if ( -f $SiteConfigBis && open(CONFIG, "$SiteConfigBis")) {
      $FileConfig = "$SiteConfigBis";
      $SiteConfig = $SiteConfigBis;
    }
  }
```

注释写「如果传入完整路径就打开」。`rel2abs` 对已经以 `/` 开头的字符串几乎是原样返回。`-f` + `open` 看的是**磁盘上的绝对路径**。过滤器刚看过的是「有没有子串 `..`」；open 看到的是 `/pcb_canary/flag.conf`。两套语义中间没有第二次谓词。

`Parse_Config` 读到 `Include "<FLAG>"` 时打不开那个「文件名就是 FLAG 字符串」的 include，错误页把 FLAG 反射进 body。金丝雀在树外能出现在 HTML 里，依据就是这一步。

---

## 仓库里已经有更强的检查，绝对路径回退没用

`Read_Config` 开头已经维护了一张「配置只该出现在这些目录」的列表，CGI 还禁止用非默认 `configdir` 覆盖（除非设了 `AWSTATS_ENABLE_CONFIG_DIR`）。搜索循环的设计意图就是：只在这些前缀下找文件。

谁遵守这张表：

| 步骤 | 受 `@PossibleConfigDir` 约束？ |
|---|---|
| 试 `awstats.$SiteConfig.conf` | 是，拼在 `$searchdir` 后面 |
| 试 `$searchdir$SiteConfig` | 是 |
| `File::Spec->rel2abs` 回退 | **否**，把 `$SiteConfig` 当独立绝对路径 |

V1 等于在调用方又做了一个**更弱**的字符串删除（只认 `..` 子串），而真正允许任意绝对路径的那次 open 始终挂着。不是仓库里没有「只在配置目录里找」的约定，是 **rel2abs 回退没用上这条约定**。

即便 `/pcb_canary/flag.conf` 没有 `..` 可剥，只要这段回退还在，任何已经绝对、且 `-f` 为真的路径都会被打开。issue #90 的报告者用 `/etc/passwd` 就是这个形状。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs open」落到具体代码：

- 解析末尾的 `s/\.\.//g`：看 `$SiteConfig` 里有没有两个点
- `rel2abs` + `open`：看这个字符串作为文件系统路径指向哪里

只要构造一种输入，使「删除 `..`」之后**剩下**的仍是绝对路径，第一行是空操作，第二行仍然打开树外文件。

绝对路径就是这样来的。`/pcb_canary/flag.conf` 六个字符里没有 `..`：

```text
config:  /pcb_canary/flag.conf

V1 s/\.\.//g：无匹配，原样
搜索循环：/etc/awstats/awstats./pcb_canary/flag.conf.conf 等都不存在
rel2abs：/pcb_canary/flag.conf
open：成功
Parse_Config：Include "PCBFLAG_..."
错误页 body 出现 FLAG
```

这正是 7.6 上 seed 想到达的那个文件。过滤器认为自己已经把穿越清干净了，实际上它只删除了一种表示，`open` 仍按绝对路径执行。

NVD CVE-2020-29600 原话：*`cgi-bin/awstats.pl?config= accepts an absolute pathname, even though it was intended to only read a file in the /etc/awstats/awstats.conf format. NOTE: this issue exists because of an incomplete fix for CVE-2017-1000501.`*

---

## 残余仍然走同一条 config= 读配置路径（CVE-2020-29600）

没有换 CGI、没有换参数名、没有换身份。还是：

```http
GET /cgi-bin/awstats.pl?config=/pcb_canary/flag.conf
```

解析器仍然写入 `$SiteConfig`，仍然跑 `s/\.\.//g`（空操作），仍然进同一个 `Read_Config`，仍然走 rel2abs 回退，仍然 `Parse_Config`，错误页仍然带出 FLAG。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里：

```text
path = /cgi-bin/awstats.pl?config=/pcb_canary/flag.conf
```

和 issue #90 / NVD 同一构造，只是把 `/etc/passwd` 换成金丝雀。认证：v1 + `--residual` 退出码 0，body 中观察到 `RUN_FLAG`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：过滤器匹配语言比路径语义窄（只认 `..`）；拼磁盘 / 绝对打开发生在检查之后；搜索目录表没有约束 rel2abs 回退。seed 被挡住只说明「带 `..` 的写法没了」，不说明「不能再让 config= 打开任意文件」。

---

## 后来又补了什么（CVE-2020-29600，7.8）

7.8（commit `d4d815d`，FIX #90）把那段绝对路径回退整段注释掉：

```perl
# V2  7.8  Read_Config
	#CL - Added to open config if full path is passed to awstats
	# Disabled by LDR for security reason.
	# If we need to execute config into other dir
	#if ( !$FileConfig ) {
	#	my $SiteConfigBis = File::Spec->rel2abs($SiteConfig);
	#	...
	#}
```

对残余输入：搜索循环找不到 `/pcb_canary/flag.conf` 对应的 `awstats.*.conf`，rel2abs 不再执行，报「Couldn't open config file」，body 没有 FLAG。公开建议是升级到 7.8。

即便如此，7.8 仍把 `/etc` 留在 `@PossibleConfigDir` 里，搜索循环仍会尝试 `$searchdir$SiteConfig`。CVE-2020-35176 随后指出：`config=passwd`（省略开头的 `/etc`）会在扫到 `/etc` 时打开 `/etc/passwd`。那是下一条链，本 case 的 V2 只关闭「完整绝对路径」这条 residual。本 benchmark 不把 35176 当本 case 的认证目标。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是解析器出口的字符串。真正逃出配置树的是 `Read_Config` 的 `rel2abs` + `open`。V2 才关掉那次回退，没有改成「realpath 必须落在允许目录前缀下」。

**不是没有更好的谓词。**  
`@PossibleConfigDir` 已经表达「只在这些目录找」。rel2abs 回退是显式的例外。从 V1 的 diff 只能看到加了 `s/\.\.//g`；要判断补丁是否闭合，必须看到 `Read_Config` 在找不到文件之后还做了什么。

**同一 CGI、同一 `$SiteConfig`，只换了路径写法。**  
任何把用户字符串传进 `config=` 的请求，在 7.7 上都吃那一行正则和同一次 rel2abs。advisory 已指出绝对路径即可。

**`Sanitize` 不是路径白名单。**  
它不剥 leading `/`，也不把值限制成 `[A-Za-z0-9._-]`。若 `config=` 只允许站点名 token，后面那行 `s/\.\.//g` 和 rel2abs 都不会被逼去近似路径安全。

**金丝雀在搜索目录外是有意的。**  
正常 `config=flag` 找不到 `/pcb_canary/flag.conf`。能读到它，说明 `open` 打开的是任意文件系统路径。

---

## 版本、入口、参考

| | tag | 解析器 | `Read_Config` | `/etc/../pcb_canary/...` seed | `/pcb_canary/flag.conf` residual |
|---|---|---|---|---|---|
| V0 | 7.6 | 无 `s/\.\.//g` | rel2abs 回退开着 | 读到金丝雀 | （不必） |
| V1 | 7.7 | `s/\.\.//g` | 同上 | 路径被剥断，找不到 | rel2abs 打开金丝雀 |
| V2 | 7.8 | 同上 | rel2abs 注释掉 | 挡 | 找不到配置，挡 |

- Web：`/cgi-bin/awstats.pl?config=...`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2017-1000501](https://nvd.nist.gov/vuln/detail/CVE-2017-1000501)、[CVE-2020-29600](https://nvd.nist.gov/vuln/detail/CVE-2020-29600)
- [eldy/awstats#90](https://github.com/eldy/awstats/issues/90)
- V1 源码：[`awstats.pl` @ tag `7.7`](https://github.com/eldy/awstats/blob/7.7/wwwroot/cgi-bin/awstats.pl)（`Read_Config`、约 L16481 的 `s/\.\.//g`）
- V1 修复 commit：[`06c0ab29`](https://github.com/eldy/awstats/commit/06c0ab29c1e5059d9e0279c6b64d573d619e1651)、[`cf219843`](https://github.com/eldy/awstats/commit/cf219843a74c951bf5986f3a7fffa3dcf99c3899)
- V2 commit：[`d4d815d`](https://github.com/eldy/awstats/commit/d4d815d0caae3dbae83ac70a1ae4581bd57cf376)
- 后续不完整： [CVE-2020-35176](https://nvd.nist.gov/vuln/detail/CVE-2020-35176)
