# Majordomo 2：一次没写完的路径消毒

- Case：`PCBV2-0143`
- 产品：Majordomo 2（邮件列表管理，Web CGI + 邮件命令）
- 链：CVE-2011-0049（20110120 → 20110203）→ CVE-2011-0063（20110203 → 20110204）
- 源码对着官方 snapshot `majordomo-20110203` 的 `lib/Majordomo.pm`、`lib/Mj/FileSpace.pm`、`bin/mj_wwwusr`。运行时是整包 tarball + Apache CGI，不是抽出来的函数。

2011 年 2 月 3 日，Majordomo 2 给 help 文件路径加了一行正则，想挡住 `../`。同一天 Nikolas Sotiriu 指出：把 `../` 换成 `./.../`，那一行会自己造出新的 `../`，而且不再扫第二遍。NVD 把这件事记成 CVE-2011-0063，并写明 *this vulnerability exists because of an incomplete fix for CVE-2011-0049*。

根因不只是「正则写窄了」。检查插在字符串上；真正打开文件的是另一套拼接；同文件里已经有禁止任意 `..` 的谓词，却只挂在写路径上。下面按请求走进去、补丁改了哪一行、消毒后怎么变成磁盘路径、`get` 为什么不拦，把这三层写完。

---

## 这块功能本来在干什么

Majordomo 2 给列表管理员和订户提供按主题拆开的帮助文档。Web 入口是 CGI `mj_wwwusr`。`Mj::CommandProps` 里 help 的 `access.default` 是 `allow`，未登录也可以查。

一次典型请求：

```http
GET /cgi-bin/mj_wwwusr?domain=lists.pcb.test&func=help&extra=overview
```

`bin/mj_wwwusr` 取出 CGI 参数，再交给解析器。help 唯一的标量参数是 `topic`，所以 URL 上的 `extra` 就是 `$request->{topic}`：

```perl
# bin/mj_wwwusr (majordomo-20110203)
$ofunc = $cgi->param('func') || 'welcome';
$extra = $cgi->param('extra');
$extra = '' unless (defined $extra);

Mj::Parser::parse_args ($request, $extra, '')
  if (defined $extra and length $extra);
```

`help_start` 不做路径规范化。它对 topic 做 `lc`、空白转下划线，然后 `(.*)` untaint（斜杠和点都会留下），拼成 `help/<topic>` 交给 `_list_file_get`。找不到主题时再试 `help/configset_<topic>`，再不行回落到 `help/unknowntopic`。`_list_file_get` 返回的是**文件系统上的绝对路径**；随后用 `IO::File` 打开，内容进 HTTP 响应：

```perl
# lib/Majordomo.pm :: help_start  (majordomo-20110203, 约 L2925–3000)
  ($request->{'topic'}) = $request->{'topic'} =~ /(.*)/; # Untaint

  ($file, %fdata) =
    $self->_list_file_get(list => 'GLOBAL',
                          file => "help/$request->{'topic'}",
                          subs => $subs,
                         );
  unless ($file) {
    # 再试 help/configset_<topic>，再试 help/unknowntopic
    ...
  }

  $self->{'get_fh'} = new IO::File $file;
  unless ($self->{'get_fh'}) {
    return 0;
  }
```

设计意图：`extra` 是主题名（`overview`、`subscribe`），文件必须落在 GLOBAL / DEFAULT / STOCK 的 help 树里。没有登录、没有写操作。成功穿越之后的效果是**读出 help 树之外的文件，并把内容反射到 CGI body**。

数据流：

```text
HTTP extra
    → mj_wwwusr  (func=help)
    → parse_args → request.topic
    → help_start
         file = "help/" . topic          ← 仍是用户字符串，未消毒
    → _list_file_get($file)
         V1：s!/?\.\./?!!g               ← 补丁插在这里，只改字符串
         $f = "$d/$file"  (STOCK:en → en/<file>)
    → _get_stock($f)
         FileSpace->get($f)
         -f "$self->{dir}/$f"            ← 真正的 open，不再查 ..
    → 返回绝对路径
    → IO::File $file → CGI body
```

---

## 原始漏洞：明文 `../`（CVE-2011-0049，snapshot 20110120）

20110120 的 `_list_file_get` 在取出 `$args{file}` 之后，直接进入搜索循环，中间没有任何 `..` 处理：

```perl
# lib/Majordomo.pm :: _list_file_get  (majordomo-20110120)
  my $file = $args{file};
  my $lang = $args{lang};

  # Account for list:sublist
  if ($list =~ /^([^:\s]+):/) {
```

Michael Brooks 公开的问题是：help 的 extra 里放 `../`，就能爬出帮助目录。本 case 的 seed 读容器金丝雀（entrypoint 写入 `/pcb_canary/flag`，在 `/usr/local/majordomo` 和 lists 树之外）：

```text
extra = "../" × 10 + "pcb_canary/flag"
```

`help_start` 交给 `_list_file_get` 的是：

```text
help/../../../../../../../../../../pcb_canary/flag
```

STOCK 默认搜索含 `STOCK:en`，拼出来是 `en/help/../../../../.../pcb_canary/flag`。FileSpace 根是 `$sitedir/files`（安装后约 `/usr/local/majordomo/files`）。从 `files/en/help/` 往上四层就到 `/usr`，十层足够到 `/`，再打开 `/pcb_canary/flag`。`help_start` 把这条绝对路径交给 `IO::File`，body 里出现 `PCBFLAG_...`。

没有鉴权。邮件接口同样能发 `help ../.../etc/passwd`；本 case 只打 Web CGI。

---

## 维护者改了什么（CVE-2011-0049 修复，20110203）

20110203 只在 `_list_file_get` 入口、拼搜索路径**之前**加了一行。和前后两个 snapshot 并排：

```perl
# V0  20110120                          （无检查）
  my $file = $args{file};
  my $lang = $args{lang};

# V1  20110203                          （CVE-2011-0049，本 case 的目标）
  my $file = $args{file};
  my $lang = $args{lang};
  # $file might have bad stuff in it
  $file =~ s!/?\.\./?!!g;

# V2  20110204                          （CVE-2011-0063）
  my $file = $args{file};
  my $lang = $args{lang};
  # $file might have bad stuff in it
  $file =~ s!\.\.!!g;
```

V1 正则的字面意思：

| 片段 | 含义 |
|---|---|
| `/?` | 可选的 `/` |
| `\.\.` | 两个点 |
| `/?` | 再一个可选的 `/` |
| `g` | 从左到右配完所有**非重叠**匹配，没有第二轮扫描 |

它删除的是「可选斜杠 + `..` + 可选斜杠」这种**字面子串**，不是规范化后的路径。没有 `while` 重扫，没有 `File::Spec`，没有「realpath 必须落在 files 根下」。

对 seed 这种明文 `../` 链，它确实够用：

```text
输入:  help/../../../../../../../../../../pcb_canary/flag
V1 后: helppcb_canary/flag
```

`/../` 全被抠掉，连 `help` 和后面文件名之间的斜杠也被吃进匹配。STOCK 里没有 `helppcb_canary/flag`，`help_start` 落到 unknowntopic，body 里没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险路径段长得像 `../`、`/../`、`..`（两端斜杠可有可无）。
2. 删掉这些子串之后，剩下的字符串里不会再出现新的 `..`。

第二点不成立。更关键的是：这一行之后，代码仍然把 `$file` 当相对路径拼到磁盘上，而且那次拼接**不再做 `..` 检查**。

---

## 消毒之后，路径怎么接到磁盘上

V1 的 `s///` 一结束，同一个函数立刻用消毒后的字符串拼候选路径（约 L3533–3592）：

```perl
# lib/Majordomo.pm :: _list_file_get  （紧接在那行 s/// 之后）
  @search  = $self->_list_config_get($list, 'file_search');
  @dsearch = ('DEFAULT:$LANG', 'DEFAULT:', 'STOCK:$LANG',
              'STOCK:en', 'STOCK:');

  for $i (@search, @dsearch) {
    ($l, $d) = split(':', $i);
    $l ||= $list; $d ||= '';

    # Build filename; no leading slashes allowed
    $f = "$d/$file"; $f =~ s!^/!!;

    ...
    if ($l eq 'STOCK') {
      @out = $self->_get_stock($f);
    }
    else {
      @out = $self->{'lists'}{$l}->fs_get($f, $args{force});
    }
```

注释写「不允许 leading slash」，实际只是 `s!^/!!`，管不住中间的 `..`。`STOCK:en` 时 `$d` 是 `en`，`$f` 变成 `en/<消毒后的 $file>`。

`_get_stock` 把 FileSpace 根固定在安装树的 `files/`，然后把 `$f` 原样交给 `get`：

```perl
# lib/Majordomo.pm :: _get_stock  (约 L3727–3732)
  unless ($self->{'sitedata'}{'filespace'}) {
    return unless ($self->{'sitedata'}{'filespace'} =
      new Mj::FileSpace("$self->{'sitedir'}/files", $self->{'backend'}));
  }
  $self->{'sitedata'}{'filespace'}->get($file);
```

真正的 open 在 `Mj::FileSpace::get`。它用 `-f` 测文件是否存在，成功则返回拼接后的绝对路径。**这里没有调用 `legal_file_name`：**

```perl
# lib/Mj/FileSpace.pm :: get  (majordomo-20110203, 约 L85–113)
sub get {
  my $self  = shift;
  my $file  = shift;
  ...
  return unless (-f "$self->{'dir'}/$file" && -r _);

  $data = $self->getdata($file);
  ...
  return ("$self->{'dir'}/$file", %$data);
}
```

Perl / 内核会按 POSIX 解析 `"$self->{dir}/$file"` 里的 `..`。过滤器刚看过的是字符串 `$file`；open 看到的是拼到 `files/` 之后、经过目录上溯的绝对路径。两套语义中间没有第二次谓词。

`help_start` 拿到的 `$file` 已经是这条绝对路径，`new IO::File $file` 把它读进响应。金丝雀在树外能出现在 body 里，依据就是这一步，而不是「help 目录里碰巧有个同名文件」。

---

## 仓库里已经有更强的检查，读路径没用

同一份 `FileSpace.pm` 里已经有专门拦穿越的函数，注释写明 *No double-dots (attempt to escape up)*：

```perl
# lib/Mj/FileSpace.pm :: legal_file_name  (约 L610–622)
sub legal_file_name {
  my $self = shift;
  my $file = shift;

  return if $file =~ m|^/|;    # No leading slashes
  return if $file =~ m|^\.|;   # No leading dots
  return if $file =~ m|//|;
  return if $file =~ m|\.\.|;  # No double-dots (attempt to escape up)
  return if $file =~ m|\\|;
  return if $file =~ m|/\.|;

  $file =~ /(.*)/;
  return $1;
}
```

谁调用它：

| 函数 | 调用 `legal_file_name`？ |
|---|---|
| `put` / `mkdir` / `delete` | 是，非法名直接拒绝 |
| `get` | **否**，只做 `"$dir/$file"` 拼接 |

V1 等于在调用方 `_list_file_get` 又做了一个**更弱**的字符串删除（只认 `/?../?` 形态，单遍），而读路径上那个「任意 `..` 都非法」的检查始终没挂上。不是仓库里没有更好的谓词，是 **get 没用**。

即便 `./.../` 没有把正则打穿，只要 `get` 继续裸拼路径，任何让 `$file` 在删除之后仍含 `..` 的写法都会变成一次真实的目录上溯。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs open」落到具体代码：

- `_list_file_get` 的 `s!/?\.\./?!!g`：看有没有子串 `../`（可带两侧 `/`）
- `FileSpace::get` 的 `-f "$dir/$file"`：看拼完之后内核怎么解析路径组件

只要构造一种输入，使「删除 `../` 子串」之后**剩下**的字符重新拼出 `../`，第一行会放行，第二行仍然向上爬。

`./.../` 就是这样来的。六个字符 `. / . . . /`。从左边扫，`/?\.\./?` 吃掉中间的 `/..`，留下首尾的 `.` 和最后的 `/`：

```text
./.../     → 删掉 "/.."  →  ../
```

全局替换对每个 `./.../` 各做一次，互不重叠，十段变成十个新的 `../`，**不会再进入正则**。

带上 `help_start` 的前缀和 STOCK:en 前缀：

```text
extra:   ./.../ × 10 + pcb_canary/flag

help_start 拼进 _list_file_get 的 $file:
  help/./..././.../ ... /pcb_canary/flag

V1 单遍 s!/?\.\./?!!g 之后:
  help/../../../../../../../../../../pcb_canary/flag

STOCK:en 再拼:
  en/help/../../../../../../../../../../pcb_canary/flag

FileSpace::get 实际测的路径:
  $sitedir/files/en/help/../../../../../../../../../../pcb_canary/flag
  → 规范化后 /pcb_canary/flag
```

这正是 20110120 上 seed 用过的那种路径。过滤器认为自己已经把 `../` 清干净了，实际上它刚造出了一批新的，并且 `get` 会按真实 `..` 打开。

V1 删的是带斜杠的 `../` 形态；`./.../` 里三个点不是两个点，整段不会被当成一次 `..` 匹配，只会抠掉嵌在中间的两个点。2011-02-03 当天 Sotiriu 给 Mozilla Bugzilla 631307 的原话就是：*`Check the regex ($file =~ s!/?\.\./?!!g;) ... It deletes ../ but what happens if i ./.../ ? ./.../ becomes ../`*。

---

## 残余仍然走同一条 help 读文件路径（CVE-2011-0063）

没有换命令、没有换 CGI、没有换身份。还是：

```http
GET /cgi-bin/mj_wwwusr?domain=lists.pcb.test&func=help&extra=./..././.../...(十段).../pcb_canary/flag
```

`help_start` 仍然调用同一个 `_list_file_get`。V1 那一行正则照样执行；执行完之后 `$file` 变成带真实 `..` 段的相对路径；`FileSpace::get` 拼到 `files/` 上打开 `/pcb_canary/flag`；`IO::File` 读进 body。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
extra = "./.../" × 10 + "pcb_canary/flag"
```

和 NSOADV-2011-003 的 PoC 同一构造，只是把 `/etc/passwd` 换成金丝雀。认证：v1 + `--residual` 退出码 0，body 中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：正则匹配语言比路径语义窄；拼磁盘发生在检查之后；读路径没有使用已经存在的 `legal_file_name`。seed 被挡住只说明「字面 `../` 没了」，不说明「不能再从 help 读出树外文件」。

---

## 后来又补了什么（CVE-2011-0063，20110204）

第二天把那一行换成删除**任意** `..`，不再要求两侧是斜杠：

```perl
-  $file =~ s!/?\.\./?!!g;
+  $file =~ s!\.\.!!g;
```

对残余输入：

```text
输入:  help/./..././.../ ... /pcb_canary/flag
V2 后: help/././././ ... /pcb_canary/flag
```

三个点里的两个被抠掉，剩下 `././`。相对路径不再向上，STOCK 找不到主题，再次落到 unknowntopic。公开建议是升级到 `majordomo-20110204`。

即便如此，这仍然是「在拼路径之后删子串」，`FileSpace::get` 还是不做 `legal_file_name`。对 `./.../` 这条已知链它够用；若还有其它让 `..` 在删除之后重新出现、或根本不以两个点字符出现的写法，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `_list_file_get` 入口的字符串。真正逃出树的是 `FileSpace::get` 的 `"$dir/$file"`。V2 仍在同一层加码，没有把读路径接到已有的 `legal_file_name`，也没有在 open 之后检查 realpath 前缀。

**不是没有更好的谓词。**  
`legal_file_name` 禁止任意 `..`，比 V1 那行正则更接近「路径安全」。它已经用在 `put` / `mkdir` / `delete` 上。help 穿越走的是 `get`。从 V1 的 diff 只能看到加了一行 `s///`；要判断补丁是否闭合，必须看到 `get` 的拼接和 `legal_file_name` 的调用点。

**同一函数、同一 `$file`，只换了 topic 的写法。**  
任何把用户字符串传进 `_list_file_get(file => ...)` 的命令，在 20110203 上都吃这一行正则和同一次 `get`。advisory 已指出邮件 `help ./.../` 同样能打。

**主题名几乎没有字符白名单。**  
`help_start` 的 `(.*)` untaint 让斜杠和点进入 `help/<topic>`。若 topic 只允许 `[A-Za-z0-9_]`，后面那行正则根本不会被逼去近似路径安全。

**金丝雀在树外是有意的。**  
`/pcb_canary/flag` 不在 DocumentRoot 或 lists 树里。能读到它，说明 `IO::File` 打开的是任意文件系统路径。

---

## 版本、入口、参考

| | snapshot | `_list_file_get` | `FileSpace::get` | 明文 `../` seed | `./.../` residual |
|---|---|---|---|---|---|
| V0 | 20110120 | 无消毒 | 裸拼 `"$dir/$file"` | 读到金丝雀 | （不必） |
| V1 | 20110203 | `s!/?\.\./?!!g` | 同上，仍不调 `legal_file_name` | 落到 unknowntopic | 读到金丝雀 |
| V2 | 20110204 | `s!\.\.!!g` | 同上 | 挡 | 变成 `././`，挡 |

- Web：`/cgi-bin/mj_wwwusr?domain=lists.pcb.test&func=help&extra=...`
- 认证（本平台 2/2）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2011-0049](https://nvd.nist.gov/vuln/detail/CVE-2011-0049)、[CVE-2011-0063](https://nvd.nist.gov/vuln/detail/CVE-2011-0063)
- [NSOADV-2011-003](http://sotiriu.de/adv/NSOADV-2011-003.txt)
- [Mozilla Bugzilla 631307](https://bugzilla.mozilla.org/show_bug.cgi?id=631307)（含 20110203→20110204 的 `Majordomo.pm` diff）
- 官方包：`https://ftp.mj2.org/pub/mj2/snapshots/2011-01/majordomo-20110120.tar.gz` 与 `2011-02/majordomo-20110203.tar.gz`、`majordomo-20110204.tar.gz`
