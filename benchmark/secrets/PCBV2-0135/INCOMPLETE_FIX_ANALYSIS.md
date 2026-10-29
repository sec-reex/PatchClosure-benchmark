# Koel 播客 SSRF：下载腿加了逐跳检查，探测腿仍跟随 302

- Case：`PCBV2-0135`
- 产品：Koel（自建音乐/播客，官方镜像 `phanan/koel`）
- 链：CVE-2026-47260 / GHSA-7j2f-6h2r-6cqc（9.3.2 → 9.3.5，commit `be1e867` / `8708f07`）→ CVE-2026-54491 / GHSA-6qvr-wjmv-v8mm（9.3.5 → 9.7.1，commit `c264a3d5` / PR #2546）
- 源码对着 GitHub tag `v9.3.5` 的 `app/Values/Podcast/EpisodePlayable.php`、`app/Services/Podcast/PodcastService.php::getStreamableUrl`、`app/Helpers/Network.php`。运行时是整台官方 Koel（nginx + PHP），非管理员 listener 走真实 `POST /api/podcasts` 与 `GET /play/{episode}`。

2026 年 5 月，9.3.5 给播客 enclosure 加上 `Network::isSafeUrl`，并在 **EpisodePlayable 下载** 上挂了 Guzzle `on_redirect`：每一跳都再跑 `isSafeUrl`，私网 302 抛 `UnsafeUrlException`。GHSA-6qvr-wjmv-v8mm 标题就是 *Incomplete fix for CVE-2026-47260*：逐跳回调只接到这一处；`getStreamableUrl` 仍是 `new Client()` + `ALLOW_REDIRECTS => ['track_redirects' => true]`，只有初始 URL 检查。

根因不只是「漏了一个 call site」。检查插在「第一次 URL 像不像公网」以及「下载腿的 on_redirect」；真正出站的还有播放前的 OPTIONS/HEAD 探测；`isSafeUrl` 已经存在且足够挡私网 IP，却没挂上探测客户端的每一跳。下面按订阅/播放走进去、9.3.5 改了哪几行、检查之后谁发起 HTTP、更强的逐跳谓词有没有挂上 sibling，把这几层写完。

平台 residual 观察的是 sidecar `/hits.log`（盲 SSRF），seed 观察的是 `/play` 响应体（全量读）。同一 `GET /play` 触发两条出站腿；残余不是无关洞，而是下载腿被挡住之后仍在跑的那条探测腿。heldout 与 V1 源码对得上。

---

## 这块功能本来在干什么

Koel 允许登录用户订阅 RSS。enclosure URL 存在 episode 的 `path` 上。点播放时服务端会：

1. `PodcastService::getStreamableUrl`：对 enclosure 做 OPTIONS（失败再 HEAD），看是否 CORS 可直链；跟随重定向并记下最终 URL。
2. `EpisodePlayable::createForEpisode`：若本地还没有缓存文件，`Http::sink($file)->get($url)` 把音频（或 302 之后的内容）拉下来，再流给用户。

本 case 的攻击者是非管理员 listener。RSS 由 PHP-公网 IP `11.0.0.10` 提供；enclosure 指向同一主机上会 302 到 PHP-私网金丝雀 `10.99.0.192` 的 URL。`filter_var(..., NO_PRIV_RANGE|NO_RES_RANGE)` 把 11.0.0.10 当成公网、10.99.0.192 当成私网。成功穿越之后的效果是：**Koel 的出站客户端跟随 302，打到只能从内部到达的 canary**。seed 把 canary body（`PCBFLAG_...`）写进 `/play` 响应；residual 只要求 canary 的 access log 非空。

数据流：

```text
POST /api/podcasts {url: http://11.0.0.10/feed.xml}
    → 解析 enclosure = http://11.0.0.10/redir   （公网，过 isSafeUrl）
GET  /play/{episode}?api_token=
    → getStreamableUrl(enclosure)
         V1：isSafeUrl(初始 URL) 然后 new Client()->request(OPTIONS)
              ALLOW_REDIRECTS track_redirects，无 on_redirect   ← 残余走这里
    → EpisodePlayable::createForEpisode
         V1：isSafeUrl + Http::sink on_redirect 里再 isSafeUrl   ← 补丁插在这里
              私网 302 → UnsafeUrlException
    → 把本地文件流回 HTTP 响应
```

设计意图：enclosure 必须是公网；重定向也不能进 RFC1918。V1 只把第二句落实在下载腿上。

---

## 原始漏洞：出站 GET 无公网约束（CVE-2026-47260，9.3.2）

9.3.2 没有 `Network::isSafeUrl`。EpisodePlayable 直接：

```php
Http::sink($file)->get($episode->path)->throw();
```

Guzzle/Laravel HTTP 默认跟随重定向。enclosure 是 `http://11.0.0.10/redir` → 302 `http://10.99.0.192/hit` → 下载到的字节就是金丝雀页面。`/play` body 里出现 `PCBFLAG_...`。v0 + `--seed` 退出码 0。canary 日志里会有 GET（以及探测腿的 OPTIONS）。

---

## 维护者改了什么（CVE-2026-47260 修复，9.3.5）

commit `8708f07` 给若干 fetch 加上初始 `isSafeUrl`。commit `be1e867`（*validate redirect targets when downloading podcast episodes*）只改 EpisodePlayable。tag `v9.3.5`：

```php
// app/Values/Podcast/EpisodePlayable.php :: createForEpisode  (v9.3.5)
$url = (string) $episode->path;

if (!Network::isSafeUrl($url)) {
    throw UnsafeUrlException::forUrl($url);
}

Http::sink($file)
    ->withOptions([
        'allow_redirects' => [
            'max' => 5,
            'on_redirect' => static function ($request, $response, $uri): void {
                if (!Network::isSafeUrl((string) $uri)) {
                    throw UnsafeUrlException::forUrl((string) $uri);
                }
            },
        ],
    ])
    ->get($url)
    ->throw();
```

同一 tag 上，探测腿：

```php
// app/Services/Podcast/PodcastService.php :: getStreamableUrl  (v9.3.5)
public function getStreamableUrl(string|Episode $url, ?Client $client = null, string $method = 'OPTIONS'): ?string
{
    $url = $url instanceof Episode ? $url->path : $url;

    if (!Network::isSafeUrl($url)) {
        return null;
    }

    $client ??= new Client();

    try {
        $response = $client->request($method, $url, [
            RequestOptions::HEADERS => [ ... ],
            RequestOptions::HTTP_ERRORS => false,
            RequestOptions::ALLOW_REDIRECTS => ['track_redirects' => true],
        ]);
        ...
```

`isSafeUrl` 最终落到 `isPublicHost`：IP 字面量用 `FILTER_FLAG_NO_PRIV_RANGE | NO_RES_RANGE`；主机名则 `dns_get_record` 后再用同一套 flag。对 seed 的**下载**腿，302 到 `10.99.0.192` 时 `on_redirect` 抛异常，文件写不下来，`/play` body 没有 flag。v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的出站跟随发生在 `Http::sink()->get()` 这一次。
2. 初始 `isSafeUrl` 对「只做探测、不把 body 流回用户」的客户端也够用。

第二点不成立。Guzzle 在 `ALLOW_REDIRECTS` 为真且没有 `on_redirect` 时，仍会向 Location 发下一跳。探测失败只返回 `null`，并不阻止请求已经打到私网。GHSA 原文：*the request uses ALLOW_REDIRECTS => ['track_redirects' => true] with no on_redirect → 302 to internal*。

---

## 消毒之后，谁真正消费那个 URL

EpisodePlayable 里，`on_redirect` 的 `$uri` 会再进 `isSafeUrl`。getStreamableUrl 里，`isSafeUrl` 只消费**第一次** `$url`；之后 `Client::request` 自己跟 302，没有回调。

播放一次 `/play` 两条腿都会跑。V1 下载腿在跳到 10.99.0.192 时炸掉；探测腿 OPTIONS 已经发出，canary 记下 `OPTIONS /hit`。oracle 的 residual 读的就是这份 log，不是 `/play` body。

所以：过滤器刚看过的是 enclosure 的初始主机；探测客户端看到的是 Location 里的私网 IP。两套语义中间没有第二次 `isSafeUrl`。

---

## 仓库里已经有更强的检查，探测客户端没用

`Network::isSafeUrl` / `isPublicHost` 正是「这一跳是不是公网」的谓词。EpisodePlayable 已经在 `on_redirect` 里调用它。getStreamableUrl 只在函数开头调用一次，然后 `new Client()`——连 Laravel `Http` facade 那份带 `on_redirect` 的 options 都没复用。

同一 9.3.5 上 GHSA 点名的其它缺口：

| 调用点 | 初始 isSafeUrl | 逐跳 on_redirect |
|---|---|---|
| `EpisodePlayable` | 是 | **是**（be1e867） |
| `getStreamableUrl` | 是 | **否** |
| `isPodcastObsolete` 的 `Http::head` | 否 | 否 |
| 若干 SafeUrl / radio 路径 | 部分 | 否 |

V2 的修法是抽出 `SafeHttp::redirectOptions()` / `guzzleClient()`，让所有出站默认带逐跳检查。不是没有更好的谓词，是 **只接到了把 body 流回用户的那一处**。advisory 原话：*Do not fix per-call-site. Centralize.*

---

## 这个补丁挡住了什么、没挡住什么

- `isSafeUrl(初始 URL)`：看 enclosure 主机此刻是不是公网（11.0.0.10 过）
- EpisodePlayable `on_redirect`：看每一跳 Location 是不是公网（10.99.0.192 不过）
- getStreamableUrl 的 Guzzle：看 `ALLOW_REDIRECTS`，默认跟随

```text
seed /play
  下载腿：on_redirect 抛 UnsafeUrlException → body 无 flag
  探测腿：OPTIONS 11.0.0.10 → 302 → OPTIONS 10.99.0.192 → hits.log 非空

residual 判定：hits.log 非空即 SSRF（不要求 flag 出现在 /play body）
```

把 enclosure `http://11.0.0.10/redir`（302 → `http://10.99.0.192/hit`）放进两条腿：

```text
初始 isSafeUrl("http://11.0.0.10/redir")
  host 11.0.0.10 → FILTER_FLAG_NO_PRIV_RANGE 通过

EpisodePlayable GET
  第一跳：11.0.0.10/redir  200/302
  on_redirect(http://10.99.0.192/hit)
    isSafeUrl → isPublicHost("10.99.0.192") → false
    throw UnsafeUrlException
  sink 文件不完整，/play 不把 canary 字节写进 body

getStreamableUrl OPTIONS
  第一跳：同一公网 URL，isSafeUrl 已通过
  Guzzle 默认跟随 Location
  第二跳：OPTIONS http://10.99.0.192/hit     ← 没有 on_redirect
  canary /hits.log 追加 "OPTIONS /hit"
```

V1 挡的是「把私网响应体当音频流回去」；它没挡「服务端已经对私网发了 OPTIONS/HEAD」。seed 被挡住只说明下载腿的 sink 不再含金丝雀。

`isPublicHost` 对 IP 字面量不再做 DNS，直接用 `filter_var`。canary 配成 `10.99.0.192` 就是为了让这个谓词在 hop 上稳定为假，避免 DNS 再解析一次把测试打滑。探测腿的问题不是谓词算错，是谓词根本没在第二跳上运行。

V1 镜像 9.3.5 已含 `8708f07` 的初始检查和 `be1e867` 的下载腿回调；缺的是把同一回调接到 `new Client()`。从 tag 上的 `PodcastService.php` 可以直接读出这个缺口，不必对照那份可能过期的 `patch.diff`。

---

## 残余仍然由同一次播放触发（CVE-2026-54491）

没有换用户、没有换 RSS、没有换 enclosure。还是 `GET /play/{episode}`。heldout 清 canary log 再播一次，看 log。认证：v1 + `--residual` 退出码 0，hits.log 中观察到探测方法。

所以残余不是新资产，而是同一 enclosure URL 上三件事叠在一起：逐跳检查按调用点挂；探测腿显式允许跟踪重定向；初始 `isSafeUrl` 不绑定后续 hop 的 IP。平台用 hits.log 而不是 `/play` body，是因为探测腿本来就不把 canary 字节写进响应——效果通道变了，出站 sink 仍是「跟随 302 打到 10.99.0.192」。

---

## 后来又补了什么（CVE-2026-54491，9.7.1）

commit `c264a3d52513a83b21e1cc3a20e895caea97fc4a`（PR #2546）增加 `App\Helpers\SafeHttp`：`redirectOptions()` 里带 `on_redirect` → `isSafeUrl`；`guzzleClient()` 给 PSR-18 消费者。`getStreamableUrl` 改为：

```php
$client ??= $this->safeHttp->guzzleClient();
$response = $client->request($method, $url, [
    ...
    RequestOptions::ALLOW_REDIRECTS => [
        ...$this->safeHttp->redirectOptions()['allow_redirects'],
        'track_redirects' => true,
    ],
]);
```

对残余：OPTIONS 的 302 目标是 10.99.0.192 时抛 `UnsafeUrlException`，canary 收不到请求。公开建议升到 9.7.1。GHSA 仍提醒 DNS rebinding（校验与连接各解析一次、无 IP pinning）是另一条腿；本 benchmark 的 v2 只关闭「探测腿跟随 302」这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「把文件 sink 到磁盘的那次 GET」。真正打到内网的还可以是同一次播放里更早的 OPTIONS。V2 把逐跳检查抽到共享 HTTP 客户端，才接近「所有出站」。

**不是没有更好的谓词。**  
`isSafeUrl` 已经在 `Network` 里，并且已经用在 EpisodePlayable 的 `on_redirect` 上。从 be1e867 只能看到下载腿；要判断是否闭合，必须看到 `getStreamableUrl` 的 `new Client()`。

**同一 enclosure、同一次 `/play`，只换了哪条腿出站。**  
订阅时写入的 URL 两边共用。初始检查两边都过，因为 11.0.0.10 是公网。

**「不把 body 给用户」不是 SSRF 的闭合条件。**  
盲探测同样证明控制器能打到私网。residual 的 oracle 按 hits.log 设计，就是为了量这条腿。

**金丝雀没有宿主机端口是有意的。**  
只有 Koel 容器所在的 internalnet 能连 10.99.0.192。log 非空说明出站客户端跟随了 302，而不是测试机直接打 canary。

订阅时 `synchronizeEpisodes` 已经对 enclosure 跑过一次 `isSafeUrl` 才入库。那只能保证**写入瞬间**的 URL 是公网；播放时 Guzzle 跟随的 Location 是另一条 URL。把检查放在「写 path 的时候」挡不住「读 path 时的 302」。探测腿和下载腿读的是同一列 `episode->path`，差别只在有没有 `on_redirect`。

---

## 版本、入口、参考

| | Koel | EpisodePlayable | getStreamableUrl | seed `/play` body | residual canary log |
|---|---|---|---|---|---|
| V0 | 9.3.2 | 无 isSafeUrl | 无 | 含 flag | （不必） |
| V1 | 9.3.5 | isSafeUrl + on_redirect | 仅初始 isSafeUrl，跟随 302 | 无 flag | OPTIONS 命中 |
| V2 | 9.7.1 | 同左或经 SafeHttp | SafeHttp 逐跳 | 挡 | log 空 |

- 入口：`POST /api/podcasts` + `GET /play/{episode}?api_token=`
- [GHSA-6qvr-wjmv-v8mm](https://github.com/koel/koel/security/advisories/GHSA-6qvr-wjmv-v8mm)（incomplete fix for CVE-2026-47260）
- [GitLab advisory CVE-2026-54491](https://advisories.gitlab.com/composer/phanan/koel/CVE-2026-54491/)
- V1 commit `be1e867`；V2 [`c264a3d5`](https://github.com/koel/koel/commit/c264a3d52513a83b21e1cc3a20e895caea97fc4a) / [PR #2546](https://github.com/koel/koel/pull/2546)
- 源码：[`v9.3.5` EpisodePlayable.php](https://github.com/koel/koel/blob/v9.3.5/app/Values/Podcast/EpisodePlayable.php)、[同 tag PodcastService.php](https://github.com/koel/koel/blob/v9.3.5/app/Services/Podcast/PodcastService.php)
- 原始 advisory：[GHSA-7j2f-6h2r-6cqc](https://github.com/advisories) / CVE-2026-47260（9.3.5 关闭下载腿全量读）
