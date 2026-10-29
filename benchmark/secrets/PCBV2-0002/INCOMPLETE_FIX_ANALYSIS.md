# Apache httpd：单遍解 `%2e`，没把 `%%32%65` 当成还没解完的点

- Case：`PCBV2-0002`
- 产品：Apache HTTP Server（本 case 跑官方 `httpd:2.4.49` / `2.4.50` / `2.4.51`，Alias `/pub/` → DocumentRoot，金丝雀在文件系统根 `/canary.txt`）
- 链：CVE-2021-41773（仅 2.4.49 → 2.4.50）→ CVE-2021-42013（2.4.49–2.4.50 → 2.4.51）
- 源码对着 `2.4.50` / `2.4.51` 的 `server/util.c` `ap_normalize_path`。运行时是整份 httpd，不是抽出来的函数。配置里 `Alias /pub/ ...` 且别名目录**没有**默认的 `Require all denied`（advisory 写明这是利用前提）。

2.4.49 重写路径规范化时漏了「第二个点仍是 `%2e`」的段。2.4.50 专门认 `.%2e`。Apache 自己的 2.4 安全页把 CVE-2021-42013 标成 *incomplete fix of CVE-2021-41773*：同一条 Alias 映射，只是点被双重百分号编码。NVD 原话：*the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient*。

根因不只是「忘了双重编码」。检查插在「当前段是不是 `.` 加上字面 `%2e`」上；真正拼到磁盘上的是规范化**之后**还可能再被解码一次的字符串。V1 的解码只走一遍，且非法的 `%`（后面不是两个 hex）会原样留下。下面按请求走进去。

---

## 这块功能本来在干什么

httpd 收到请求后，在做 Alias / ScriptAlias / 访问控制之前，先把 URL 路径收成「没有多余斜杠、没有 `.` / `..` 段」的形式。这是 `ap_normalize_path` 的工作。随后 `ap_core_translate` / `try_alias_list` 把规范化后的 URL 映射到文件系统，`apr_filepath_merge` 再和服务器根拼在一起。

一次典型请求（本 case 的 Alias 是 `/pub/` → htdocs）：

```http
GET /pub/.%2e/%2e%2e/%2e%2e/%2e%2e/canary.txt HTTP/1.1
```

数据流（2.4.50，本 case 的 V1）：

```text
HTTP request-target
    → ap_process_request_internal
         ap_normalize_path(path, AP_NORMALIZE_DECODE_UNRESERVED | ...)
              1. 若 flags 含 DECODE_UNRESERVED：
                   %XX 且解码后是 ALPHA/DIGIT/-._~ → 原地换成字符
                   只做一遍，% 后面不是两个 hex 就跳过
              2. 折叠 //
              3. 去掉 /./
              4. 去掉 /xx/../
                 V1 额外：第二个点可以是字面 %2e / %2E
         失败（越出根）则 400
    → Alias / ScriptAlias 用规范化后的 URL 匹配 /pub/
    → apr_filepath_merge(DocumentRoot 或 Alias 目标, 剩余路径)
         内核 / APR 再解析路径里剩下的 .. 或后续解码
    → 打开文件，body 进 HTTP 响应
```

设计意图：规范化之后路径必须落在 Alias 配置的目录里。金丝雀在 `/canary.txt`，DocumentRoot 够不着；普通 `GET /canary.txt` 是 404。成功穿越之后的效果是**读出 Alias 树之外的文件，并把内容反射到响应 body**。

---

## 原始漏洞：`.%2e` 不会被当成 `..`（CVE-2021-41773，2.4.49）

2.4.49 把旧的 `ap_normalize_path` 换成更接近 RFC 3986 的实现，并在规范化时解码 unreserved 百分号。去 `..` 的分支当时只认第二个字符是字面 `.`：

```c
/* 2.4.49 逻辑（V0）：当前段以 '.' 开头时 */
if (path[l] == '.') {
    /* Remove /./ */
    if (IS_SLASH_OR_NUL(path[l + 1])) { ... }

    /* Remove /xx/../  —— 只看 path[l+1] 是不是 '.' */
    if (path[l + 1] == '.' && IS_SLASH_OR_NUL(path[l + 2])) {
        /* Wind w back to remove the previous segment */
        ...
    }
}
```

对 seed 段 `.%2e`：

```text
读指针在 '.'
path[l+1] 是 '%'，不是 '.'  →  不折叠
把 '.' 抄进输出
下一轮 '%2e' 被 DECODE_UNRESERVED 解成 '.' 再抄进输出
结果：输出里留下真的 '..'
```

`%2e%2e` 同理：第一个 `%2e` 解成 `.` 后，第二个 `%2e` 还没解，去点分支看到的是 `.%2e`，同样不折叠。四段这样的 `..` 从 htdocs 走到 `/`，再打开 `/canary.txt`。

本 case seed：

```text
GET /pub/.%2e/%2e%2e/%2e%2e/%2e%2e/canary.txt
```

2.4.49 上 HTTP 200，body 里是 `PCBFLAG_...`。这是 2021 年 10 月被大规模扫描的那条链；advisory 写 *known to be exploited in the wild*。默认配置里 DocumentRoot 之外是 `Require all denied`，所以利用依赖 Alias-like 指令把 URL 映射到一块**没有**这条默认拒绝的目录——本 case 的 `/pub/` 就是这样配的。

---

## 维护者改了什么（CVE-2021-41773 修复，2.4.50）

2.4.50 的 `ap_normalize_path`（tag `2.4.50`，`server/util.c`）在去 `..` 时加了一条：第二个点可以是**还没解的字面 `%2e`**。解码开关被收成局部变量，避免重复测 flag。

```c
// server/util.c :: ap_normalize_path  (httpd 2.4.50)
    apr_size_t l = 1, w = 1, n;
    int decode_unreserved = (flags & AP_NORMALIZE_DECODE_UNRESERVED) != 0;
    ...
        if (decode_unreserved
                && path[l] == '%' && apr_isxdigit(path[l + 1])
                                  && apr_isxdigit(path[l + 2])) {
            const char c = x2c(&path[l + 1]);
            if (apr_isalnum(c) || (c && strchr("-._~", c))) {
                l += 2;
                path[l] = c;
            }
        }
    ...
                /* Remove /xx/../ segments (or /xx/.%2e/ when
                 * AP_NORMALIZE_DECODE_UNRESERVED is set since we
                 * decoded only the first dot above).
                 */
                n = l + 1;
                if ((path[n] == '.' || (decode_unreserved
                                        && path[n] == '%'
                                        && path[++n] == '2'
                                        && (path[++n] == 'e'
                                            || path[n] == 'E')))
                        && IS_SLASH_OR_NUL(path[n + 1])) {
                    /* Wind w back to remove the previous segment */
                    ...
                    l = n + 1;
```

注释自己承认：unreserved 解码**只解了第一个点**，所以要特判第二个还是 `%2e`。对 seed `.%2e` / `%2e%2e` 这确实够用——折叠发生，路径被收进 Alias 目录甚至被 `AP_NORMALIZE_NOT_ABOVE_ROOT` 打成失败 → 400。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的第二个点，要么已经是 `.`，要么是三个字符 `%` `2` `e`（大小写 e）。
2. `DECODE_UNRESERVED` 一遍之后，不会再留下「看起来不像 `%2e`、但再解一次又是点」的串。

第二点不成立。解码循环对每个 `%` 只看后面两个字符是不是 hex；若不是，**原样保留这个 `%`**，然后继续往右扫。

---

## 消毒之后，路径怎么接到磁盘上

V1 的 `ap_normalize_path` 返回 1 之后，同一个请求里 Alias 匹配的是这份**已经写回 `path[]` 的字符串**。它不再跑第二遍规范化。`apr_filepath_merge` 把 Alias 目标目录和剩余 URL 拼成 OS 路径；APR / 内核会解析真的 `..`，部分映射路径上残留的 `%2e` 还会再被当成百分号解码。

也就是说：过滤器刚看过的是「段内有没有 `.` + `%2e`」；open 看到的是拼完之后、可能又解了一层百分号的文件系统路径。中间没有「输出里不许再出现 `%`」的谓词。

`ap_getparents` 仍然存在，内部也调 `ap_normalize_path`，但核心请求路径不会在 Alias 之后再叫一次更严的版本。

---

## 仓库里已经有更强的检查，规范化出口没用

同文件稍后：

```c
// server/util.c :: ap_getparents  (2.4.50)
AP_DECLARE(void) ap_getparents(char *name)
{
    if (!ap_normalize_path(name, AP_NORMALIZE_NOT_ABOVE_ROOT |
                                 AP_NORMALIZE_DECODE_UNRESERVED)) {
        name[0] = '\0';
    }
}
```

这是「规范化失败就清空」的包装，不是「解码直到稳定」或「拒绝残留 `%`」。V1 选择在去 `..` 分支里**枚举** `%2e` 这一种写法，而不是：

- 把 unreserved 解码做成 `while (path[l]=='%')` 直到当前字符不再是百分号；
- 或者：解码之后若还留着 `%` 就 `return 0`（非法编码）。

第二种正是 2.4.51 补上的。不是仓库里没有「路径必须干净」的意图，是 V1 把谓词写在「第二个点的字形」上，而不是写在「解码结果」。

---

## 这个补丁挡住了什么、没挡住什么

点 `.` 的百分号是 `%2e`。再编一次：`%` → `%25` 不是这条 residual 用的；residual 把 `2` 编成 `%32`、把 `e` 编成 `%65`，前面再留一个裸 `%`：

```text
.   →  %2e        →  %%32%65
..  →  %2e%2e     →  %%32%65%%32%65
```

对输入段 `%%32%65`，V1 的单遍解码：

```text
位置 0: '%'  后面是 '%'，不是 hex  →  不解码，把 '%' 抄进输出
位置 1: '%32'  →  数字 '2' 是 unreserved  →  输出 '2'
位置 4: '%65'  →  字母 'e' 是 unreserved  →  输出 'e'

规范化输出:  %2e
```

去 `..` 分支此时看到的字符是 `%`，不是 `.`，特判 `%2e` 也不会在「当前段以点开头」里触发。输出里留下 `%2e`。下一段同样留下 `%2e`。Alias 把 `/pub/` 剥掉之后，剩余路径带着 `%2e%2e` 走进 `apr_filepath_merge`；再解一层（或按 `%2e` 当点）就变成真的 `..`，从 htdocs 爬到 `/canary.txt`。

Qualys 的表述和这条变换一致：2.4.49 用 `.%2e`，2.4.50 把同一个点改成 `%%32%65`。

```text
seed:      /pub/.%2e/%2e%2e/%2e%2e/%2e%2e/canary.txt
residual:  /pub/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/canary.txt
```

四段双重编码的 `..` 仍然是从 `/pub/` 对应的目录走到文件系统根，再读金丝雀。

---

## 残余仍然走同一条 Alias 读文件路径（CVE-2021-42013）

没有换模块、没有换 Alias、没有换金丝雀。还是 GET 到 `/pub/.../canary.txt`，还是 `ap_normalize_path` → Alias → `apr_filepath_merge` → 打开 `/canary.txt`。

本 case residual candidate：

```text
SEG  = "%%32%65%%32%65"
PATH = "/pub/" + SEG + "/" + SEG + "/" + SEG + "/" + SEG + "/canary.txt"
```

Apache 2.4 安全页把这记成 *incomplete fix of CVE-2021-41773*。认证：v1 + `--residual` 退出码 0，body 中观察到 `PCBFLAG_...`；2.4.51 上同一 URL 是 400。

seed 被挡住只说明「字面 `%2e` 作为第二个点没了」，不说明「不能再从 Alias 读出树外文件」。

---

## 后来又补了什么（CVE-2021-42013，2.4.51）

2.4.51 的解码分支改成：只要当前是 `%`，后面两个必须是 hex，否则整条路径非法（`ret = 0` → 请求 400）。提交 r1893977 / r1893980 / r1893982。

```c
// server/util.c :: ap_normalize_path  (httpd 2.4.51)
        if (decode_unreserved && path[l] == '%') {
            if (apr_isxdigit(path[l + 1]) && apr_isxdigit(path[l + 2])) {
                const char c = x2c(&path[l + 1]);
                if (TEST_CHAR(c, T_URI_UNRESERVED)) {
                    l += 2;
                    path[l] = c;   /* 解完落在当前读指针，下面立刻当 '.' 处理 */
                }
            }
            else {
                /* Invalid encoding */
                ret = 0;
            }
        }
```

`%%32%65` 的第一个 `%` 后面是 `%`，不是 hex → `ret = 0` → 400。残余链断在规范化入口，Alias 根本看不到那条路径。

公开建议：直接升级到 2.4.51（不要停在 2.4.50）。CISA KEV 两条都收了。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是「去 `..` 时第二个点的字形」。真正逃出 Alias 目录的是规范化**输出**里残留的 `%2e` 再经 `apr_filepath_merge`。V2 把谓词改成「任何非法 `%` 都失败」，才碰到输出字母表。

**不是没有更好的谓词。**  
把解码做成直到稳定，或禁止输出中再出现 `%`，都能盖住 `%%32%65`。V1 只枚举了 `%2e` 这一种「还没解的点」。从 V1 的 diff 只能看到 `path[n]=='%' && '2' && 'e'`；要判断是否闭合，必须把 `%%32%65` 亲手走一遍单遍解码，看输出是不是还剩 `%2e`。

**同一函数、同一 Alias，只换了点的编码层数。**  
任何让 `ap_normalize_path` 输出里重新出现 `%2e` / `..` 的写法，都会再进一次 `apr_filepath_merge`。

**金丝雀在 DocumentRoot 外是有意的。**  
`/canary.txt` 不是 web 文件。能读到它，说明 merge 之后打开的是任意文件系统路径。

---

## 版本、入口、参考

| | 版本 | `ap_normalize_path` | 明文 `.%2e` seed | `%%32%65` residual |
|---|---|---|---|---|
| V0 | 2.4.49 | 去 `..` 只认第二个字面 `.` | 读到金丝雀 | （不必） |
| V1 | 2.4.50 | 第二个点可认字面 `%2e`；非法 `%` 原样保留 | 400 | 读到金丝雀 |
| V2 | 2.4.51 | `%` 后必须是两个 hex，否则失败 | 挡 | 400 |

- Web：`GET /pub/.%2e/%2e%2e/%2e%2e/%2e%2e/canary.txt`（seed）；`GET /pub/%%32%65%%32%65/.../canary.txt`（residual）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 400；v1 residual 观察到。
- [CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)、[CVE-2021-42013](https://nvd.nist.gov/vuln/detail/CVE-2021-42013)
- [Apache 2.4 安全页](https://httpd.apache.org/security/vulnerabilities_24.html)（42013 标题即 *incomplete fix of CVE-2021-41773*；fix r1893977, r1893980, r1893982）
- [Qualys 2021-10-27](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013)
- V1 源码：[`server/util.c` @ 2.4.50](https://github.com/apache/httpd/blob/2.4.50/server/util.c) `ap_normalize_path`
- V2 源码：[`server/util.c` @ 2.4.51](https://github.com/apache/httpd/blob/2.4.51/server/util.c)
