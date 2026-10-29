# PHP：`__Host-` 检查挂在第一轮 mangling 之后，未闭合 `[` 的第二轮才把名字变成受保护前缀

- Case：`PCBV2-0168`
- 产品：PHP 解释器（`php-src`）。公开 API 是 Cookie 头 → `$_COOKIE` 超全局。本 case 用一小段 PHP 只读 `$_COOKIE['__Host-flag']` 并 JSON 反射，运行时是 pinned 的 PHP 8.1.x，不是应用自己的解析器。
- 链：CVE-2022-31629（GHSA-c43m-486j-j32p，8.1.10 → 8.1.11，`php_register_variable_ex` 在第一轮 `.`/` `→`_` 之后丢弃「mangling 才变成 `__Host-`/`__Secure-`」的名字）→ CVE-2024-2756（GHSA-wpj3-hf5j-x4v4，8.1.11 → 8.1.28，把同一谓词接到未匹配 `]` 的恢复路径和 `plain_var` 注册点）。NVD / GHSA 原文：*Due to an incomplete fix to CVE-2022-31629*。
- 源码对着 tag `php-8.1.11` 的 `main/php_variables.c`。V0 是 `php-8.1.10`。V2 是 `php-8.1.28`。

**平台 residual 先说清：** 当前 `scripts/verify.sh` 的 `--residual` 分支只是再跑一遍 `original_poc.py`，cookie 名仍是 `..Host-flag`。那是 **seed 向量**，在 V1 已经被第一轮检查丢掉，**不是** CVE-2024-2756 那条不完全修复链。公开 residual 是 GHSA 给出的 `_[Host-x`（未闭合方括号，走第二轮 `[`→`_`）。下面按解释器源码和 advisory 写；不要把 verify 的复制 seed 当成 2756。

根因不只是「忘了几种点号组合」。检查插在「第一轮替换之后名字是不是 `__Host-`」上；真正写入 `$_COOKIE` 的是后面 `plain_var` 里的 `php_register_variable_quick`。同函数里已经有「未匹配 `]` 时把 `[` 也换成 `_`」的第二轮 mangling，V1 的 Host 检查发生在它**之前**。下面按 Cookie 头走进去。

---

## 这块功能本来在干什么

应用信任浏览器的 cookie 前缀：只有当前 host、`Secure`、`Path=/` 的响应才能 Set-Cookie `__Host-flag=…`。跨站页面设不了这个名字。PHP 把收到的 Cookie 头登记进 `$_COOKIE` 时，会把名字里的 `.` 和空格换成 `_`（以及下面要说的 `[` 恢复路径）。

本 case 应用：

```php
$protected = $_COOKIE['__Host-flag'] ?? null;
echo json_encode(['__Host-flag' => $protected, 'collision' => $protected !== null, ...]);
```

一次典型攻击（原始 cookie 名，客户端不做规范化）：

```http
GET /
Cookie: ..Host-flag=PCBFLAG_…
```

浏览器不把 `..Host-flag` 当 `__Host-` 前缀，任意站点都能种。PHP 若把它登记成 `$_COOKIE['__Host-flag']`，应用就会把攻击者给的值当成高完整性会话。成功穿越之后的效果是 **受保护槽位里出现探针写入的 flag 字符串**。

数据流：

```text
Cookie: <name>=<flag>
    → SAPI 拆 cookie
    → php_register_variable_ex(var_name, val, $_COOKIE)
         拷贝名字
         第一轮：' ' / '.' → '_'；遇到 '[' 则当作数组起点并截断
         V1：若 mangled 以 __Host- 开头且原始不以 __Host- 开头 → 丢弃
         若 '[' 后没有 ']'：恢复 '[' 为 '_'，再把剩余的 ' ' / '.' / '[' → '_'
         goto plain_var → php_register_variable_quick(最终名字)
    → $_COOKIE['__Host-flag']
    → JSON 反射
```

---

## 原始漏洞：点号 mangling 撞上 `__Host-`（CVE-2022-31629，8.1.10）

V0 没有 Host 前缀检查。第一轮把 `..Host-flag` 变成 `__Host-flag`，直接登记。bugs.php.net 81727 / GHSA-c43m-486j-j32p：网络或同站攻击者能种一个浏览器不当成 Host 前缀的 cookie，PHP 应用却当成 `__Host-` / `__Secure-`。本 case seed 用 `..Host-flag`。v0 的 JSON 里 `__Host-flag` 等于探针的 flag。

---

## 维护者改了什么（CVE-2022-31629，8.1.11）

V1 在第一轮循环之后、处理数组下标之前插入：

```c
/* main/php_variables.c :: php_register_variable_ex  (php-8.1.11, 约 L93–118) */
	for (p = var; *p; p++) {
		if (*p == ' ' || *p == '.') {
			*p='_';
		} else if (*p == '[') {
			is_array = 1;
			ip = p;
			*p = 0;
			break;
		}
	}
	var_len = p - var;

	/* Discard variable if mangling made it start with __Host-, where pre-mangling it did not */
	if (strncmp(var, "__Host-", sizeof("__Host-")-1) == 0
	    && strncmp(var_name, "__Host-", sizeof("__Host-")-1) != 0) {
		zval_ptr_dtor_nogc(val);
		free_alloca(var_orig, use_heap);
		return;
	}
	/* 对 __Secure- 同样一段 */
```

对 seed：

```text
var_name = "..Host-flag"
第一轮后 var = "__Host-flag"
strncmp(var, "__Host-")==0 且 原始不是 → return，不登记
```

JSON 里没有受保护槽。这就是 v1 + `--seed` 退出码 10（也是当前 verify `--residual` 会得到的结果，因为它仍发 `..Host-flag`）。

`__Secure-` 紧挨着同一段逻辑，只是前缀长度不同。CVE-2024-2756 两条前缀一起修。本 case 应用只读 `__Host-flag`，分析沿这条槽位写；`_[Secure-…` 是对称 residual。

第一轮之前还有 `while (*var_name==' ') var_name++;`，丢掉**前导空格**。前导空格不会变成 `_`，所以 `  __Host-flag` 这种不会靠空格撞前缀。会撞前缀的是名字**内部**的 `.` / 空格 / 第二轮的 `[`。

补丁默认：所有会把普通 cookie 变成 `__Host-` 的 mangling，都发生在这一轮 `.`/` ` 替换里。

---

## 第一轮之后，未闭合 `[` 怎么再改一次名字

同一函数在 `is_array` 分支里找 `]`。找不到时：

```c
			ip = strchr(ip, ']');
			if (!ip) {
				/* not an index; un-terminate the var name */
				*(index_s - 1) = '_';
				/* PHP variables cannot contain ' ', '.', '[' … replace with '_' */
				for (p = index_s; *p; p++) {
					if (*p == ' ' || *p == '.' || *p == '[') {
						*p = '_';
					}
				}
				index_len = 0;
				if (index) {
					index_len = strlen(index);
				}
				goto plain_var;
			}
```

对 GHSA-wpj3 的 PoC `Cookie: _[Host-x=y`：

```text
第一轮：'_' 保留，'[' 令 is_array=1，把 '[' 写成 NUL，var 变成 "_"
Host 检查：var 是 "_"，不以 __Host- 开头 → 放行
无 ']'：把刚才的 NUL 写成 '_'，再把剩余里的 '[' 换成 '_'
最终 index = "__Host-x"
goto plain_var → 登记 $_COOKIE["__Host-x"]="y"
```

V1 谓词看过的是截断后的 `"_"`；消费者 `php_register_variable_quick` 拿到的是第二轮之后的 `"__Host-x"`。两套名字中间没有第二次 Host 检查。GHSA 原话：*cookies starting with `_[Host-` are parsed by PHP applications as `__Host-`*。

本 case 应用读的是 `__Host-flag`，所以公开 residual 应是 `_[Host-flag`（无闭合 `]`）。verify 若仍发 `..Host-flag`，打的是已经闭合的 seed，不是这条链。

---

## 仓库里已经有更强的检查，第二轮没用

V1 已经写出「mangling 前后前缀不一致就丢弃」。它只调用了一次，键是第一轮的 `var`。第二轮明确注释 *replace the characters with a '_'*，包含 `[`——这正是另一种 mangling。`plain_var` 在 8.1.11 **不再查** Host。不是没有谓词，是 **谓词没有挂在最终登记点**。

V2 把谓词提成 `php_is_forbidden_variable_name(mangled, len, pre_mangled)`，在 `plain_var` 和数组下标两条登记路径上都调用，用的是**即将写入哈希表的那个名字**对比原始 `var_name`。

---

## 这个补丁挡住了什么、没挡住什么

- V1：第一轮之后 `var` 是否变成 `__Host-` / `__Secure-`
- `plain_var`：最终 `index` 写进 `$_COOKIE`

`..Host-flag` 在第一轮就已经是 `__Host-flag`，被丢掉。`_[Host-flag` 在第一轮不是，检查跳过；第二轮才变成受保护名并登记。bugs.php.net 81727 的报告人在 31629 落地后多次重报，直到 8.1.28。

若 cookie 写成 `_[Host-flag]=x`（带闭合括号），第一轮截断 `var="_"`，然后 `strchr` 找到 `]`，走真正的数组路径：`$_COOKIE['_']['Host-flag']`，**不会**撞上 `__Host-flag`。2756 依赖的是「`[` 出现了、`]` 没有出现」，这才触发 un-terminate + 第二轮把 `[` 换成 `_`。GHSA PoC 的 `_[Host-x=y` 没有 `]`，不是笔误。

`plain_var` 对 cookie 还有 rfc2965 去重：同名已存在则跳过。碰撞发生在**第一次**登记该名字时。应用若先 Set-Cookie 了真的 `__Host-flag`，后到的 mangled 名会被跳过；本 case 应用不种该 cookie，槽位空着，碰撞即写入。

---

## 残余仍然走同一条 Cookie → $_COOKIE（CVE-2024-2756）

没有换超全局、没有换应用槽位。还是：

```http
Cookie: _[Host-flag=<flag>
```

`php_register_variable_ex` 仍跑 V1 那次检查（对 `"_"` 无效）；未匹配 `]` 的恢复把名字变成 `__Host-flag`；应用 JSON 反射出 flag。同一 sink。平台 verify 复制 seed **没有**走这一步——若认证 residual 失败，原因是脚本发错了名字，不是 8.1.11 已经闭合 2756。

---

## 后来又补了什么（CVE-2024-2756，8.1.28）

```c
static bool php_is_forbidden_variable_name(const char *mangled_name, size_t mangled_name_len,
    const char *pre_mangled_name)
{
	if (mangled_name_len >= sizeof("__Host-")-1
	    && strncmp(mangled_name, "__Host-", sizeof("__Host-")-1) == 0
	    && strncmp(pre_mangled_name, "__Host-", sizeof("__Host-")-1) != 0) {
		return true;
	}
	/* __Secure- 同样 */
	return false;
}
```

`plain_var`（约 L267）和数组分支在 `zend_symtable` 更新之前都调用它。`_[Host-flag` 的最终 mangled 名是 `__Host-flag`，原始不是，丢弃。建议升到 8.1.28 / 8.2.18 / 8.3.5。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是第一轮之后的中间名字。真正进 `$_COOKIE` 的是可能经过第二轮的 `index`。V2 把谓词移到登记点。

**不是没有更好的谓词。**  
「mangling 才得到的 `__Host-` 非法」在 8.1.11 已经写了。未闭合 `[` 路径自己也在做 mangling。从 31629 的 diff 只能看到第一处 `strncmp`；要判断闭合，必须把 `goto plain_var` 读完。

**同一函数、同一超全局，只换了让第二轮触发的 `[`。**  
任何读 `$_COOKIE['__Host-…']` / `__Secure-…` 的 PHP 应用，在 8.1.11–8.1.27 上都吃这条恢复路径。

**平台 residual 目前不是 2756。**  
`verify.sh` 的 else 分支把 `original_poc.py` 再跑一遍，cookie 名固定 `..Host-flag`。那是 31629 seed，V1 已丢弃。要驱动不完全修复链，应发未闭合方括号的 `_[Host-flag=<flag>`（与 GHSA PoC `_[Host-x=y` 同构）。写分析时以 `php_variables.c` 和 GHSA-wpj3 为准，不以 verify 的复制 seed 为准。

**V2 测试向量覆盖了两轮。**  
8.1.28 回归里 `..Host-` / `._Host-` / `.[Host-` 属第一轮或混合，`_[Host-` 属未闭合 `[`。`php_is_forbidden_variable_name` 用最终 mangled 名对比原始 `var_name`，两轮都收。

**应用侧无法用「我只读 `__Host-flag`」自救。**  
碰撞发生在登记进超全局之前。PHP 代码看见的已经是合法槽位。闭合必须在 `php_register_variable_ex`。

**8.1.11 上两个 Cookie 名对照。**

```text
# seed
Cookie: ..Host-flag=<flag>
第一轮 '.'→'_' → var="__Host-flag"
Host 检查：mangled 是前缀、原始不是 → 丢弃

# residual（GHSA-wpj3；verify.sh 目前没发这条）
Cookie: _[Host-flag=<flag>
第一轮：var="_"（在 '[' 截断），检查不命中
无 ']'：'[' 改成 '_' → index="__Host-flag"
plain_var 登记 → $_COOKIE['__Host-flag']=<flag>
```

同一 `php_register_variable_ex`、同一应用槽位。差别是 Host 检查插在第几轮 mangling 之后。

---

## 版本、入口、参考

| | tag | Host 检查位置 | `Cookie: ..Host-flag=` | `Cookie: _[Host-flag=` |
|---|---|---|---|---|
| V0 | php-8.1.10 | 无 | 撞上受保护槽 | 同样撞上 |
| V1 | php-8.1.11 | 仅第一轮后 | 丢弃 | 第二轮登记，撞上 |
| V2 | php-8.1.28 | `plain_var` + 数组路径 | 丢弃 | 丢弃 |

- 库/运行时 API：Cookie 头 → `$_COOKIE['__Host-flag']`
- 本 case HTTP：`GET /` + 原始 `Cookie` 行
- [CVE-2022-31629](https://nvd.nist.gov/vuln/detail/CVE-2022-31629)、[CVE-2024-2756](https://nvd.nist.gov/vuln/detail/CVE-2024-2756)
- [GHSA-c43m-486j-j32p](https://github.com/php/php-src/security/advisories/GHSA-c43m-486j-j32p)、[GHSA-wpj3-hf5j-x4v4](https://github.com/php/php-src/security/advisories/GHSA-wpj3-hf5j-x4v4)（含 `_[Host-x=y` PoC）
- [bugs.php.net 81727](https://bugs.php.net/bug.php?id=81727)
- V1：[php_variables.c @ php-8.1.11](https://github.com/php/php-src/blob/php-8.1.11/main/php_variables.c)
- V2：[php_variables.c @ php-8.1.28](https://github.com/php/php-src/blob/php-8.1.28/main/php_variables.c)
