# OpenSSL c_rehash：hash 计算改成 list-form open，check_file 的两参数 open 仍会喂 shell

- Case：`PCBV2-0160`
- 产品：OpenSSL `c_rehash`（Perl CLI，给证书目录建 hash 符号链接）。运行时是从 tag `OpenSSL_1_1_1o` **整树编译**出的真实 `tools/c_rehash`，对含恶意**文件名**的目录执行。无 HTTP。
- 链：CVE-2022-1292（1.1.1n → 1.1.1o，commit `e5fd1728`）→ CVE-2022-2068（1.1.1o → 1.1.1p，commit `9639817d`）
- OpenSSL 2022-06-21 advisory 原话：*In addition to the c_rehash shell command injection identified in CVE-2022-1292, further circumstances where the c_rehash script does not properly sanitise shell metacharacters … were found by code review. When the CVE-2022-1292 was fixed it was not discovered that there are other places in the script where the file names of certificates being hashed were possibly passed to a command executed through the shell.*

根因不只是「文件名没转义」。检查（换成 list-form `open $fh, '-|', @_`）插在 **hash 计算**上；真正还会把文件名交给 shell 的，是更早的 `check_file` 里两参数 `open IN, $fname`。同一份 V1 脚本的 `link_hash_cert` 无 symlink 回退路径已经用了三参数 `open($in, '<', $fname)`。下面按 CLI 走进去。

平台 residual 打的是 **同一脚本里的另一处 Perl 原语**，不是另一个 OpenSSL 工具（例如 `openssl rehash` C 实现）。advisory 把这定义为 1292 的 incomplete-fix；seed 的 sink 是反引号/`compute_hash`，residual 的 sink 是 `check_file` 的 2-arg `open`。两条都是「攻击者控制的证书文件名进 shell」，但**不是**同一次 `open`。

---

## 这块功能本来在干什么

`c_rehash <dir>` 扫描目录里的 `.pem/.crt/.cer/.crl`，用 `openssl x509 -subject_hash` 算出名字，再 `symlink` 成 `<hash>.0`。发行系统有时在包脚本里自动跑它。一次典型调用：

```bash
c_rehash /tmp/certs
```

攻击面是目录里的**文件名**，不是 PEM 内容。设计意图：文件名是普通路径，可以拼进 `openssl ... -in "$fname"`。成功穿越之后的效果是：**以运行 c_rehash 的用户执行文件名里的 shell 元字符**。本 case 的 payload 只把 `${PCB_FLAG}` echo 进目录里的相对文件，不连外网。

数据流：

```text
c_rehash $CERTDIR
    → hash_dir
         readdir → 每个 *.pem
         check_file($fname)
              V0/V1：open IN, $fname          ← 两参数，"|" 会走 shell
              V2：open(my $in, "<", $fname)   ← 三参数，当文件
         若是证书 → link_hash_cert($fname)
              V0：`"$openssl" x509 ... -in "$fname"`   ← 双引号反引号，$( ) 会执行
              V1：compute_hash($openssl, "x509", ..., "-in", $fname)
                   open($fh, "-|", @_)                 ← list-form，不经 shell
    → 注入命令若跑起来，目录里出现 orig_out / resid_out，含 PCBFLAG_...
```

不需要网络。有的 OS 在更新 CA 包时自动执行，advisory 按这个威胁模型给了 Moderate。官方已经建议改用 `openssl rehash`。

`hash_dir` 用 `grep {/\.(pem)|(crt)|(cer)|(crl)$/}` 选文件。这不是「扩展名等于 `.pem`」，而是「名字匹配这个正则」。`a.pem;echo $PCB_FLAG>resid_out|` 里有 `.pem`，能进循环。V0 seed `z$(echo $PCB_FLAG>orig_out).pem` 同样以 `.pem` 结尾。内容可以是一份最小自签证书，也可以几乎为空——`check_file` 先 open 再扫 BEGIN 行；管道注入发生在扫之前。

环境变量 `SSL_CERT_DIR` 或命令行目录参数决定扫描哪棵树。本 case 把恶意名字种在容器内的证书目录，然后 `c_rehash` 那个目录。攻击者模型是：能往被 rehash 的目录里写文件（共享 CA 目录、解压上传的 zip、CVE 场景里的自动脚本）。

---

## 原始漏洞：反引号把文件名交给 shell（CVE-2022-1292，1.1.1n）

1.1.1n 的 `link_hash_cert`（patch.diff 删除的那几行）和 `check_file` 并排：

```perl
sub check_file {
    my $fname = $_[0];
    open IN, $fname;     # 两参数，V0/V1 相同
    while(<IN>) { ... }
}

sub link_hash_cert {
    my $fname = $_[0];
    $fname =~ s/\"/\\\"/g;
    my ($hash, $fprint) = `"$openssl" x509 $x509hash -fingerprint -noout -in "$fname"`;
```

只转义 `"`。文件名 `z$(echo $PCB_FLAG>orig_out).pem` 落在双引号里，`$(...)` 仍由 `/bin/sh` 执行。`link_hash_crl` 用单引号包 `$fname`，同样挡不住单引号闭合。Elison Niven / Sophos 报的就是这条。这就是 v0 + `--seed`：`ORIG_OUT` 里出现 flag。

同一版本的 `check_file` 已经是 `open IN, $fname`。seed 文件名以 `.pem` 结尾、不含管道，两参数 `open` 当普通文件读，注入发生在后面的反引号。所以 seed 专门打 hash 计算这一处；不是 V0 上 `check_file` 安全，而是 seed 没去触发它的 shell 形态。

---

## 维护者改了什么（CVE-2022-1292 修复，1.1.1o）

commit `e5fd1728` *c_rehash: Do not use shell to invoke openssl*。tag `OpenSSL_1_1_1o` 的 `tools/c_rehash.in`：

```perl
# V1  1.1.1o   （本 case 的目标）
sub compute_hash {
    my $fh;
    if ( $^O eq "VMS" ) {
        if (!open($fh, "-|", join(' ', @_))) { ... }
    } else {
        if (!open($fh, "-|", @_)) {            # list-form，不经 shell
            print STDERR "Cannot compute hash on '$fname'\n";
            return;
        }
    }
    return (<$fh>, <$fh>);
}

sub link_hash_cert {
    my $fname = $_[0];
    my ($hash, $fprint) = compute_hash($openssl, "x509", $x509hash,
                       "-fingerprint", "-noout", "-in", $fname);
```

`open $fh, '-|', $openssl, 'x509', ..., '-in', $fname` 是 exec 参数列表，`$(...)` 不再经过 shell。seed 文件名当 `-in` 的路径，openssl 打开失败或读到怪名字，**不会** echo flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 「文件名进 shell」发生在调用 `openssl` 算 hash 的那一行。
2. 换成 list-form 之后，脚本里就没有别的 shell 了。

第二点不成立。`check_file` 仍是两参数 `open`。更关键的是：V1 **同一函数文件**里，无 symlink 时的拷贝路径已经写了三参数 `open($in, "<", $fname)`——更强的原语就在几行之外。

---

## 消毒之后，文件名怎么接到 check_file 上

`hash_dir` 对每个匹配扩展名的名字**先** `check_file` 再 `link_hash_cert`：

```perl
# OpenSSL_1_1_1o  tools/c_rehash.in
FILE: foreach $fname (grep {/\.(pem)|(crt)|(cer)|(crl)$/} @flist) {
    my ($cert, $crl) = check_file($fname);
    ...
    link_hash_cert($fname) if ($cert);
}

sub check_file {
    my ($is_cert, $is_crl) = (0,0);
    my $fname = $_[0];
    open IN, $fname;          # 两参数；未见三参数模式
    while(<IN>) {
        if (/^-----BEGIN (.*)-----/) { ... }
    }
    close IN;
    return ($is_cert, $is_crl);
}
```

Perl 两参数 `open` 把名字当表达式：末尾 `|` 表示「把这串交给 shell，从管道读 stdout」；开头 `-|` / `|-` 是另一种管道。`open IN, $fname` 没有显式模式字符时，Perl 从字符串里猜。过滤器（`compute_hash`）刚保证「调用 openssl 不经 shell」；`check_file` 看到的仍是攻击者的文件名字符串。两套语义中间没有第二次「文件名只能当路径」。

`check_file` 只是为了看文件里有没有 `-----BEGIN CERTIFICATE-----`。它甚至不需要成功读到 PEM：管道命令的输出若不含 BEGIN，函数返回 `(0,0)`，`hash_dir` 打印 WARNING 然后 `next`——**注入已经发生**。所以 residual 不必让 openssl 算出 hash，也不必通过 `link_hash_cert`。

residual 文件名（case 记录的形态）：

```text
a.pem;echo $PCB_FLAG>resid_out|
```

仍匹配 `grep {/\.pem$/}`（名字里有 `.pem`）。Perl 看到的 `open` 表达式等价于把该字符串当命令跑，stdout 接到 `IN`。`echo $PCB_FLAG>resid_out` 在 `c_rehash` 的 cwd（证书目录）写下 flag 文件。`compute_hash` 即使稍后失败也无所谓——注入已经在 check 阶段发生。

把两条链并排：

```text
seed     文件名: z$(echo $PCB_FLAG>orig_out).pem
         V0 打 link_hash_cert 的 `"$openssl" ... "$fname"`
         V1 compute_hash list-form → $( ) 不执行

residual 文件名: a.pem;echo $PCB_FLAG>resid_out|
         V0/V1 都打 check_file 的 open IN, $fname
         V1 的 compute_hash 与这次注入无关
```

金丝雀出现在 `resid_out`，依据是这次 **2-arg open**，不是反引号。

---

## 仓库里已经有更强的检查，check_file 没用

同一份 1.1.1o 脚本：

| 调用点 | 如何打开 `$fname` |
|---|---|
| `compute_hash`（V1 新增） | list-form `open $fh, '-|', @_` |
| `link_hash_cert` 无 symlink 的拷贝 | `open($in, "<", $fname)` 三参数 |
| `check_file` | **`open IN, $fname` 两参数** |
| `link_hash_crl` 无 symlink | V1 仍 `system("cp", $fname, $hash)`（列表形式，相对安全） |

三参数 `open ... '<'` 把名字当路径，管道元字符无效。不是 Perl 里没有更好的谓词，是 **check_file 没用**。`link_hash_crl` 在 V1 仍把 `$fname` 交给 `compute_hash`（已加固），无 symlink 时用 `system("cp", $fname, $hash)` 列表形式。CVE-2022-2068 advisory 说 code review 还找到「further circumstances」；1.1.1p 把拷贝收成 `copy_file` 的三参数 `open`，避免任何残留的 shell `cp` 拼接。本 case residual 不依赖 `cp`，`check_file` 一条就够。

从 `e5fd1728` 的 diff 只能看到「反引号改成 compute_hash」；要判断是否闭合，必须把 `check_file` 整段读完，并 grep 全部 `open` / 反引号 / `system`。

---

## 这个补丁挡住了什么、没挡住什么

- `compute_hash`：看能否在不经过 shell 的情况下 exec openssl
- `check_file` 的 `open IN, $fname`：看 Perl 是否把名字当 shell 表达式

`$(...)` 打不进 list-form，所以 seed 死。带尾 `|` 的名字不经过 `compute_hash` 也能在 `check_file` 里执行。OpenSSL 自己在 code review 里发现了「还有别的地方把文件名交给 shell」——Daniel Fiala 找到的就是这类残余（Chancen / 青藤 73lab 先报）。

---

## 残余仍然走同一条 c_rehash 目录扫描（CVE-2022-2068）

没有换工具、没有换扩展名过滤。还是：

```bash
c_rehash "$CERTDIR"    # 目录里有 a.pem;echo $PCB_FLAG>resid_out|
```

V1 的 `compute_hash` 照样存在、照样不执行这条名字里的 `echo`；`check_file` 的两参数 `open` 先跑，shell 写出 `resid_out`。公开 residual 与 seed 同属「证书文件名 → shell」，但 **sink 原语不同**：seed 是 `link_hash_cert` 的命令替换，residual 是 `check_file` 的 2-arg `open`。必须把这一点写清楚，不能当成「同一行反引号换一种 quoting」。

NVD / 2022-06-21 advisory 把 2068 写成 1292 的后续，依据就是「修 1292 时没扫完脚本里其它会把文件名交给 shell 的地方」。平台 residual 命中的正是那处漏网，不是 `openssl rehash` C 工具、也不是 `c_rehash` 的 symlink 调用。

---

## 后来又补了什么（CVE-2022-2068，1.1.1p）

tag `OpenSSL_1_1_1p` 的 `check_file`：

```perl
open(my $in, "<", $fname);
while(<$in>) {
```

拷贝抽成 `copy_file`，一律三参数。`link_hash` 合并 cert/crl。对残余：`open '<', $fname` 试图打开一个叫 `a.pem;echo ...|` 的文件，不经 shell，写不出 `resid_out`。公开建议：1.1.1p / 3.0.4 / 1.0.2zf；并改用 `openssl rehash`。

即便如此，脚本仍信任目录里任意 `.pem` 名去做 open/symlink。对「管道文件名」这条已知链，三参数够用。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是调用 openssl 的那一行。文件名在 `hash_dir` 里还有别的消费者。V2 才把 `check_file` 接到已经存在的三参数 `open`。

**不是没有更好的谓词。**  
同文件拷贝路径在 V1 已经是 `open($in, "<", $fname)`。从 1.1.1o 的 diff 只能看到新增 `compute_hash`；要判断是否闭合，必须 grep 整个 `c_rehash.in` 里的 `open` / 反引号 / `system`。

**同一 `$fname`、同一次 `readdir`，只换了哪一次 open 被打中。**  
任何能往 `SSL_CERT_DIR` 丢文件的人，在 1.1.1o 上都先经过 `check_file`。

**扩展名过滤不是白名单路径。**  
`grep {/\.(pem)|(crt)|(cer)|(crl)$/}` 只要求名字**匹配**这组后缀模式，不禁止 `;` `|` `$()`。Perl 的 `open` 模式猜测发生在扩展名过滤**之后**。把过滤理解成「这些文件是证书」并不蕴含「这些名字是路径」。

1.1.1o 的 `compute_hash` 在 VMS 上仍 `join(' ', @_)` 再 `open '-|'`，注释写 *file names are safe there*。本 case 跑的是非 VMS。那条分支说明作者知道「list-form 才不经 shell」，却只在算 hash 时用。

---

## 版本、入口、参考

| | tag | hash 计算 | `check_file` | `$(...)` seed | 尾 `|` residual |
|---|---|---|---|---|---|
| V0 | OpenSSL_1_1_1n | 双引号反引号 | 两参数 `open IN, $fname` | 写出 orig_out | （不必；同样能打） |
| V1 | OpenSSL_1_1_1o | list-form `compute_hash` | **仍两参数** | 不经 shell | 写出 resid_out |
| V2 | OpenSSL_1_1_1p | 同上 | 三参数 `open '<', $fname` | 挡 | 当路径打开，挡 |

- CLI：`c_rehash <cert-dir>`（由 entrypoint 在含恶意文件名的目录上调用真实二进制）
- V1 blob：tag [`OpenSSL_1_1_1o`](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1o/tools/c_rehash.in) `check_file` / `compute_hash`；V2 [`OpenSSL_1_1_1p`](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1p/tools/c_rehash.in)
- [CVE-2022-1292](https://www.openssl.org/news/secadv/20220503.txt)（2022-05-03 advisory）
- [CVE-2022-2068](https://www.openssl.org/news/secadv/20220621.txt)（2022-06-21 advisory）
- [NVD CVE-2022-2068](https://nvd.nist.gov/vuln/detail/CVE-2022-2068)
- 修复提交：[e5fd1728](https://github.com/openssl/openssl/commit/e5fd1728ef4c7a5bf7c7a7163ca60370460a6e23)、[9639817d](https://github.com/openssl/openssl/commit/9639817dac8bbbaa64d09efad7464ccc405527c7)
