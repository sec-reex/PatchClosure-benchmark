# AWStats 7.8：关掉了绝对路径 fallback，却把 `/etc` 留在搜索目录里

- Case：`PCBV2-0046`（`awstats-cve-2020-35176`）
- 产品：AWStats（Perl CGI 日志分析）。本 case 用 git tag `7.7`/`7.8`/`7.9` 整树，经 Apache `mod_cgid` 提供 `/cgi-bin/awstats.pl`。
- 链：CVE-2020-29600（相对 CVE-2017-1000501 / issue #90：7.8 注释掉 `File::Spec->rel2abs` 绝对路径 fallback）→ CVE-2020-35176（7.9 从 `@PossibleConfigDir` 去掉 `"/etc"`）。NVD：*`config=` accepts a partial absolute pathname (omitting the initial /etc) ... this issue exists because of an incomplete fix for CVE-2017-1000501 and CVE-2020-29600.*
- 源码对着 tag `7.8` / `7.7` / `7.9` 的 `wwwroot/cgi-bin/awstats.pl`（`Read_Config`、查询串里对 `$SiteConfig` 的 `s/\.\.//g`）。本仓库 `patch.diff` 是 ROUND9 误同步的 `HTMLMainDownloads` 饼图条件，**不是**安全增量。

2020 年 12 月，7.8 把 `Read_Config` 末尾「若还没打开文件，就把 `config=` 当绝对路径 `rel2abs` 再 open」整段注释掉，并写 *Disabled by LDR for security reason*。字面 `config=/etc/pcb_canary/flag.conf` 不再被当绝对路径打开。同一函数开头的搜索列表仍包含 `"/etc"`，循环第三种尝试是 `open($searchdir.$SiteConfig)`。把前缀 `/etc` 拿掉，留下 `pcb_canary/flag.conf`，轮到 `/etc` 时拼出来的仍是 `/etc/pcb_canary/flag.conf`。下面按 CGI 走进去、7.8 注释了哪一段、搜索循环还 open 什么、部分路径为什么还能读到树外 include 错误页上的 flag，把这三层写完。

---

## 这块功能本来在干什么

AWStats CGI 用 `config=` 选择站点配置文件，通常是 `/etc/awstats/awstats.<SiteConfig>.conf`。`Read_Config` 在一组目录里找三种文件名：`awstats.$SiteConfig.conf`、`awstats.conf`、以及 **就叫 `$SiteConfig` 的文件**。找到则 parse；配置里的 `Include` 打不开时，错误页会把 Include 的路径（以及本 case 写进那一行的 flag）反射出来。

金丝雀是 entrypoint 写的 `/etc/pcb_canary/flag.conf`，内容一行：

```text
Include "PCBFLAG_..."
```

它在 `/etc` 下，但不在 `/etc/awstats`。正常 `config=mysite` 只找 `awstats.mysite.conf` 这类名字，碰不到它。只有 `config=` 让搜索/打开落到这个路径时，parse 才会走到那条 Include，错误页出现 flag。

一次典型请求：

```http
GET /cgi-bin/awstats.pl?config=/etc/pcb_canary/flag.conf
```

数据流：

```text
QueryString config=
    → Sanitize → $SiteConfig
    → $SiteConfig =~ s/\.\.//g          ← 只删字面 ..
    → Read_Config
         foreach @PossibleConfigDir:
              试 awstats.$SiteConfig.conf
              试 awstats.conf
              试 $searchdir.$SiteConfig   ← 裸拼
         V0 7.7：若仍失败，rel2abs($SiteConfig) 再 open
         V1 7.8：rel2abs 段整段注释
    → Parse → Include "FLAG" 失败 → HTML 错误页带 FLAG
```

设计意图：`config=` 是站点短名（`mysite`），文件必须落在 awstats 配置目录里。成功穿越之后的效果是 **读出配置搜索目录之外（相对「只应读 awstats*.conf」）的文件，并把 Include 目标反射到 CGI body**。

---

## 原始漏洞：绝对路径 fallback（CVE-2020-29600，7.7）

7.7 的 `Read_Config` 在目录循环之后还有：

```perl
# awstats.pl :: Read_Config  (tag 7.7, 约 L1784–1798)
#CL - Added to open config if full path is passed to awstats
if ( !$FileConfig ) {
    my $SiteConfigBis = File::Spec->rel2abs($SiteConfig);
    debug("Finally, try to open an absolute path : $SiteConfigBis", 2);

    if ( -f $SiteConfigBis && open(CONFIG, "$SiteConfigBis")) {
        $FileConfig = "$SiteConfigBis";
        ...
        $SiteConfig=$SiteConfigBis;
    }
}
```

`config=/etc/pcb_canary/flag.conf` 已经是绝对路径，`rel2abs` 几乎原样，`-f` 成功，直接 parse。Include 行把 flag 反射到错误页。这就是 v0 + `--seed` 退出码 0。issue #90 / CVE-2017-1000501 是更早的同类问题；29600 针对的是这条仍活着的 fallback。

主循环里 `@PossibleConfigDir` 在 7.7 已经包含 `"/etc"`。所以 7.7 上 **部分路径** `config=pcb_canary/flag.conf` 其实也能经 `/etc` + 裸拼打开。seed 用全绝对路径，对应 29600 那条 fallback；7.8 关掉的是它。

---

## 维护者改了什么（CVE-2020-29600，7.8）

7.8 把上面整段包进注释，留下 *Disabled by LDR for security reason*：

```perl
# awstats.pl :: Read_Config  (tag 7.8, 约 L1752–1762)
#CL - Added to open config if full path is passed to awstats
# Disabled by LDR for security reason.
# If we need to execute config into other dir
#if ( !$FileConfig ) {
#	my $SiteConfigBis = File::Spec->rel2abs($SiteConfig);
#	...
#	if ( -f $SiteConfigBis && open(CONFIG, "$SiteConfigBis")) {
#		...
#	}
#}
```

查询串侧仍有：

```perl
$SiteConfig =~ s/\.\.//g; 		# Avoid directory transversal
```

只删字面 `..`。不删斜杠，不要求 `$SiteConfig` 匹配 `^[A-Za-z0-9_-]+$`，不要求最终路径前缀落在 `/etc/awstats`。

对 seed 这种带前导 `/` 的绝对路径：rel2abs 不再跑。搜索循环里 `$searchdir.$SiteConfig` 会变成 `/etc//etc/pcb_canary/flag.conf` 或 `/etc/awstats//etc/pcb_canary/...` 这类双前缀，`-f` 失败。找不到配置则走「Couldn't open config file」通用错误，**不 parse 金丝雀，错误页没有 Include 行里的 FLAG**。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险 `config=` 是「已经绝对」的路径，关掉 rel2abs 就够。
2. 剩下的搜索只会打开 awstats 自己的 conf 命名。

第二点不成立。循环第三种尝试打开的就是 `$searchdir.$SiteConfig`，文件名完全由用户给；搜索目录里有 `"/etc"`。

---

## 消毒之后，文件名怎么接到磁盘上

7.8 的 `@PossibleConfigDir`（约 L1682–1688）：

```perl
my @PossibleConfigDir = (
    "$DIR",
    "/etc/awstats",
    "/usr/local/etc/awstats", "/etc",
    "/etc/opt/awstats"
);
```

注释自己写着 *Other possible directories : "/usr/local/etc/awstats", "/etc"*。循环：

```perl
foreach (@PossibleConfigDir) {
    my $searchdir = $_;
    if ( $searchdir && $searchdir !~ /[\\\/]$/ ) { $searchdir .= "/"; }
    # 1) awstats.$SiteConfig.conf
    # 2) awstats.conf
    # 3) $searchdir.$SiteConfig     ← 用户字符串当相对文件名
    if ( -f $searchdir.$SiteConfig && open( CONFIG, "$searchdir$SiteConfig" ) ) {
        $FileConfig = "$searchdir$SiteConfig";
        last;
    }
}
```

没有「realpath 必须在 /etc/awstats 下」。第三种尝试的设计是允许把完整文件名（相对某个搜索根）传给 `config=`。把搜索根设成整个 `/etc` 时，相对名就可以指向 `/etc` 下任意文件。

`$SiteConfig =~ s/\.\.//g` 对 `pcb_canary/flag.conf` 是空操作：没有 `..`，没有前导 `/`。

---

## 这个补丁挡住了什么、没挡住什么

- 注释掉的 rel2abs：看 `$SiteConfig` 本身是不是已经能当绝对路径打开
- 搜索循环第三枝：看 `$searchdir . $SiteConfig` 在哪个搜索根下存在

只要构造一种输入，使「它自己不是绝对路径」（seed 那种前导 `/` 没有了），但拼上某个仍在列表里的根之后等于原先那个文件，第一段放行（根本不跑），第二段仍然 open 同一 inode。

`pcb_canary/flag.conf` 就是这样来的。省略的是搜索根 `"/etc"`，不是 `..` 爬升。issue #195 里 Beuc 写的原话：把 `config=/etc/passwd` 改成 `config=passwd`，7.8 仍在 parse `/etc/passwd`；`config=apache2/apache2.conf` 仍打开 `/etc/apache2/apache2.conf`。他期望的是只允许 `/etc/awstats/awstats*.conf`。

带上本 case 金丝雀：

```text
config=pcb_canary/flag.conf

s/\.\.//g 无改动
搜索到 "/etc" 时:
  /etc/awstats.pcb_canary/flag.conf.conf  不存在
  /etc/awstats.conf                       未必是金丝雀
  /etc/pcb_canary/flag.conf               存在 → open → Include "PCBFLAG_..."
错误页: Could not open include file: ... PCBFLAG_...
```

过滤器认为自己已经不能打开绝对路径了，实际上它把「绝对路径的前缀」做成了默认搜索根。

---

## 残余仍然走同一条 Read_Config（CVE-2020-35176）

没有换 CGI、没有换参数名。还是 `GET /cgi-bin/awstats.pl?config=...`。唯一差别是省略 `/etc/` 前缀。

`verify.sh` 的 residual 写死为 `config=pcb_canary/flag.conf`。和 #195 的 `config=passwd` 同一构造。认证：v1 + `--residual` 退出码 0，body 中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上两件事叠在一起：关掉了「把用户字符串当绝对路径」；没关掉「把用户字符串拼到 `/etc/` 后面当相对路径」。seed 被挡住只说明「全绝对路径没了」，不说明「不能再让 AWStats parse `/etc` 下任意文件」。

Beuc 还注明：这通常需要默认 `/etc/awstats/awstats.conf` **不存在**（多站点、无默认配置），否则循环可能先命中通用 `awstats.conf` 提前 last。本 case 镜像按这个前提布置，金丝雀路径才会轮到第三枝。

---

## 后来又补了什么（CVE-2020-35176，7.9）

7.9 从列表里拿掉 `"/etc"`，注释也删了那一项：

```perl
# tag 7.9
my @PossibleConfigDir = (
    "$DIR",
    "/etc/awstats",
    "/usr/local/etc/awstats",
    "/etc/opt/awstats"
);
```

`pcb_canary/flag.conf` 只会拼成 `/etc/awstats/pcb_canary/flag.conf` 等，金丝雀不在这些目录下，open 失败，错误页没有 FLAG。Debian 另有 7.8-2 的发行补丁；上游 tag 是 7.9。issue #195 关闭于 PR #196。

即便如此，第三枝仍然接受任意相对文件名，只是根不再是整个 `/etc`。对本条 partial-path 链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 7.7 与 7.8 的搜索列表其实一样

`@PossibleConfigDir` 在 7.7 和 7.8 都是 `$DIR`、`/etc/awstats`、`/usr/local/etc/awstats`、`/etc`、`/etc/opt/awstats`。29600 的 diff 几乎只动 rel2abs 那一块。所以「部分路径」在 7.7 上本来就能打；选全绝对路径当 seed，是为了让 v1 对 seed 失败（rel2abs 关掉 + 前导 `/` 让拼接对不上），对 residual 成功（去掉 `/etc` 前缀）。这是同一函数上两条打开方式，不是两个 CGI。

`Sanitize` 之后立刻 `s/\.\.//g`。`pcb_canary/flag.conf` 没有点点，也没有前导斜杠。`config=/passwd` 在 #195 里拼出 `/etc//passwd`（根 `/etc` + 用户 `/passwd`），内核当成 `/etc/passwd`。本 case residual 不用前导斜杠，拼出来是干净的 `/etc/pcb_canary/flag.conf`。

Include 反射：金丝雀文件不是要当合法 AWStats 配置跑完整个报表，而是故意 `Include` 一个不存在的路径（flag 字符串本身）。parse 在 Include 处失败，HTML 把目标路径打进 *Could not open include file*。body 里出现 `PCBFLAG_` 表示 **那份 conf 被当成配置打开并解析了**，不是目录列表碰巧打印了文件名。

7.9 拿掉 `/etc` 之后，第三枝仍接受任意相对名，只是根变成 `/etc/awstats` 等。若金丝雀种在 `/etc/awstats/pcb_canary/flag.conf`，7.9 仍可能打开——那不是本 case 的布置。本 case 把文件放在 `/etc/pcb_canary/`，专门落在「7.8 的 `/etc` 根能到、7.9 的 awstats 根不能到」的位置。

查询串解析在 `Read_Config` 之外（约 L17191）：`config=([^&]+)` 捕获后 `Sanitize`，再 `s/\.\.//g`。`Sanitize` 不是路径白名单，挡的是 HTML/脚本字符一类。`configdir=` 另有 `AWSTATS_ENABLE_CONFIG_DIR` 才能覆盖搜索根；本 case 不碰 `configdir`，只用默认五元素列表。把 `configdir=/` 当绕过是另一条链，7.8 对非默认 configdir 已加环境变量门；residual 不需要它。

#195 还演示 `config=apache2/apache2.conf` 打开发行版的 `/etc/apache2/apache2.conf`。机制与 `pcb_canary/flag.conf` 相同：相对名、搜索根 `/etc`、第三枝裸拼。本 case 不用 `/etc/passwd` 当效果通道，因为 passwd 不是 AWStats 配置、Include 反射不稳定；金丝雀文件故意是一行 Include。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「循环失败之后的绝对路径 fallback」。真正还能读 `/etc/passwd` 的是循环第三枝加上列表里的 `"/etc"`。V2 改的是列表，不是「只允许 `awstats*.conf` 这种文件名」。

**不是没有路径消毒。**  
`s/\.\.//g` 从很早就在。它管的是 `..` 段，不管「相对名 + 过宽的搜索根」。从 7.8 的注释块只能看到 rel2abs 被关掉；要判断是否闭合，必须看到 `@PossibleConfigDir` 和 `$searchdir.$SiteConfig`。

**同一 CGI、同一 `config=`，只换了省略哪一段前缀。**  
#195 的 `passwd`、`apache2/apache2.conf` 和本 case 的 `pcb_canary/flag.conf` 是同一枝。

**金丝雀用 Include 反射是有意的。**  
flag 不在 HTML 模板里。能读到它，说明 AWStats 把那份 conf 当配置 parse 了，并且 Include 目标出现在错误页。

---

## 版本、入口、参考

| | 版本 | rel2abs fallback | `@PossibleConfigDir` 含 `/etc` | seed `config=/etc/pcb_canary/flag.conf` | residual `config=pcb_canary/flag.conf` |
|---|---|---|---|---|---|
| V0 | 7.7 | 开 | 是 | parse，错误页含 flag | （亦可，不作为 seed） |
| V1 | 7.8 | 注释掉 | 是 | 找不到配置，无 flag | `/etc/`+相对名，错误页含 flag |
| V2 | 7.9 | 仍注释 | 否 | 挡 | 拼不到金丝雀，无 flag |

- Web：`GET /cgi-bin/awstats.pl?config=...`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2020-29600](https://nvd.nist.gov/vuln/detail/CVE-2020-29600)、[CVE-2020-35176](https://nvd.nist.gov/vuln/detail/CVE-2020-35176)
- [eldy/awstats#195](https://github.com/eldy/awstats/issues/195)、PR #196、commit `96756d7` / `0d4d4c0`
- tag `7.7`/`7.8`/`7.9` 的 `Read_Config`、`$SiteConfig =~ s/\.\.//g`
