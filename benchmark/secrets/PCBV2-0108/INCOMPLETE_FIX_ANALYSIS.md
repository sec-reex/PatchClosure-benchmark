# fast-jwt 公钥分类：正则加了 `^`，公钥路径却不 `trim`

- Case：`PCBV2-0108`（legacy `fast-jwt-cve-2026-34950`）
- 产品：npm `fast-jwt`（nearform）。本 case 用发布包 `createVerifier`，admin 路由用服务器 **RSA 公钥** 验签，且不显式限制 `algorithms`。
- 链：CVE-2023-48223 / GHSA-c2ff-88x2-x9pg（3.3.1 → 3.3.2，commit `15a6e92`，公钥 PEM 改正则）→ CVE-2026-34950 / GHSA-mvf2-f6gm-w987（…6.1.0 → 6.2.0，公钥路径先 `trim`）
- 源码对着 GitHub tag `v3.3.2` / `v6.2.0` 的 `src/crypto.js`：`publicKeyPemMatcher`、`performDetectPublicKeyAlgorithms`、`performDetectPrivateKeyAlgorithm`。运行时装的是发布包本身。

2023 年 11 月，fast-jwt 修算法混淆：不能把 RSA 公钥字节当 HMAC 密钥去验 HS256。3.3.2 把「字符串 `.includes('-----BEGIN PUBLIC KEY-----')`」换成「行首锚定的 PEM 正则」，并覆盖 PKCS1 的 `BEGIN RSA PUBLIC KEY`。2026 年 4 月 GHSA-mvf2-f6gm-w987 标题就是 *Incomplete fix for CVE-2023-48223*。NVD CVE-2026-34950：*the publicKeyPemMatcher regex ... uses a ^ anchor that is defeated by any leading whitespace*。

根因不只是「少剥空白」。检查插在「PEM 头在不在 index 0」这一层；真正决定允许哪些 alg 的是 `performDetectPublicKeyAlgorithms` 的返回值（`rsaAlgorithms` vs `hsAlgorithms`）；同文件里私钥路径已经 `key.trim()`，公钥路径没有。下面按请求走进去、3.3.2 改了哪一行、分类结果谁消费、trim 挂在哪，把这几层写完。

---

## 这块功能本来在干什么

服务端用 RSA 密钥对签发；verifier 却常被配成「只给公钥、不写死 algorithms」，让库根据密钥形状推断允许的 alg。一次典型管理请求：

```http
GET /admin
Authorization: Bearer <JWT>
```

本 case 另有 `/admin-tainted`：verifier 的 key 是 `"\n" + publicKeyPem`（GHSA 场景：从数据库读出的 PEM 带前导换行）。`/pubkey` 公开 PKCS1 公钥。设计意图：只有用对应私钥做 RS256（等）签出来的、且 `role=admin` 的 token 才能进。成功穿越之后的效果是：**库把公钥当成 HMAC 密钥，攻击者用公钥字节签 HS256，验签通过**，JSON 里出现 `PCBFLAG_...`。

数据流：

```text
Bearer token + 配置里的公钥字符串
    → createVerifier({ key: pubPem })
    → detectPublicKeyAlgorithms(key)
         → performDetectPublicKeyAlgorithms(key)
              V1：key.match(/^-----BEGIN( RSA)? PUBLIC KEY-----/)   ← 补丁插在这里
              命中 → 走 RSA/EC 解析；不命中且非证书 → return hsAlgorithms
    → 允许的 alg 集合里包含 HS256
    → verifySignature('HS256', key, ...) 用同一串字节做 HMAC
    → payload.role === 'admin' → flag
```

没有登录。判断完全信任分类器对「这是公钥还是共享密钥」的读法。公钥是公开的，攻击者不需要私钥。

---

## 原始漏洞：PKCS1 头匹配不上（CVE-2023-48223，fast-jwt 3.3.1）

3.3.1 用子串包含判断 SPKI 头：

```javascript
// src/crypto.js  (fast-jwt@3.3.1，概念)
const publicKeyPemMatcher = '-----BEGIN PUBLIC KEY-----'
// performDetectPublicKeyAlgorithms:
//   key.includes(publicKeyPemMatcher)  → 当作公钥
//   否则 → hsAlgorithms
```

PKCS1 公钥头是 `-----BEGIN RSA PUBLIC KEY-----`，**不包含** `BEGIN PUBLIC KEY` 这段连续字符（中间多了 `RSA `）。`.includes` 为假，函数落到「不是 PEM，当成明文 secret」，返回 `['HS256','HS384','HS512']`。攻击者用**去掉空白后的公钥字节**做 HMAC 密钥签发 HS256，verifier 用同一串字节验过。

本 case 的 seed：

```text
secret = PUB          # PKCS1 PEM，无前导空白
alg    = HS256
payload.role = admin
```

3.3.1 分类为 HMAC，`/admin` 200，body 含 flag。私钥检测路径当时已经能认 `BEGIN RSA PRIVATE KEY`；公钥路径不对称。

---

## 维护者改了什么（CVE-2023-48223 修复，3.3.2）

commit `15a6e92` / tag `v3.3.2` 把匹配器换成行首正则，并加上可选的 ` RSA`：

```javascript
// src/crypto.js  (github.com/nearform/fast-jwt tag v3.3.2)
const privateKeyPemMatcher = /^-----BEGIN(?: (RSA|EC|ENCRYPTED))? PRIVATE KEY-----/
const publicKeyPemMatcher = /^-----BEGIN( RSA)? PUBLIC KEY-----/
const publicKeyX509CertMatcher = '-----BEGIN CERTIFICATE-----'
```

分类函数（同一文件 `performDetectPublicKeyAlgorithms`）：

```javascript
function performDetectPublicKeyAlgorithms(key) {
  if (key.match(privateKeyPemMatcher)) {
    throw new TokenError(TokenError.codes.invalidKey, 'Private keys are not supported for verifying.')
  } else if (!key.match(publicKeyPemMatcher) && !key.includes(publicKeyX509CertMatcher)) {
    // Not a PEM, assume a plain secret
    return hsAlgorithms
  }

  if (key.includes(publicKeyX509CertMatcher)) {
    key = createPublicKey(key).export({ type: 'spki', format: 'pem' })
  }

  const keyData = PublicKey.decode(key, 'pem', { label: 'PUBLIC KEY' })
  // ... OID → rsaAlgorithms / ES* / EdDSA ...
}
```

对 **干净的** PKCS1 公钥（行首就是 `-----BEGIN RSA PUBLIC KEY-----`）：

- `publicKeyPemMatcher` 命中，不会早退到 `hsAlgorithms`
- 随后 `PublicKey.decode(..., { label: 'PUBLIC KEY' })` 按 **SPKI** 标签解码 PKCS1，抛错
- 外层 `detectPublicKeyAlgorithms` 包成 `Unsupported PEM public key.`

seed 在 V1 的 `/admin` 因此 401。这就是 v1 + `--seed` 退出码 10。dossier 把这记成 quirk：干净 PKCS1 在 3.3.2 上不是「正确分类为 RSA」，而是「解码失败被拒绝」。对「不能当 HMAC」这一目标，拒绝也算挡住。

补丁默认了两件事：

1. 公钥 PEM 头出现在字符串 **index 0**。
2. 私钥路径上那种「先 trim 再 match」的习惯，公钥不需要。

第二点不成立。`^` 把「头在不在串里」收成了「头是不是第一个字符」。

GHSA 描述的 6.x 中间形态还带 `publicKeyPemMatch[1] === 'RSA'` 分支；**3.3.2 实际代码**是上面这段「match 失败 → HMAC；match 成功 → 当 SPKI decode」。分析必须以 tag `v3.3.2` 为准。

---

## 检查之后，谁真正消费那个分类结果

`detectPublicKeyAlgorithms` 把返回值缓存后交给 verifier：允许的 alg 列表。若是 `hsAlgorithms`，HS256 合法，`verifySignature` 走：

```javascript
// src/crypto.js :: verifySignature  (v3.3.2)
if (type === 'HS') {
  return timingSafeEqual(
    createHmac(alg, key).update(input).digest(),
    signature
  )
}
```

`key` 就是配置里那一整串，**包括前导 `\n`**。攻击者用同一串（也带 `\n`）做 HMAC 密钥，两边一致。

过滤器刚看过的是「正则在 index 0 能不能配上 PEM 头」；HMAC 看到的是完整字节。两套语义中间没有「trim 后再分类」的第二次谓词。分类失败（当 HMAC）和分类抛错（Unsupported PEM）在 HTTP 上一个 200、一个 401。

---

## 仓库里已经有更强的检查，公钥路径没用

同一文件的私钥检测 **先 trim**：

```javascript
function performDetectPrivateKeyAlgorithm(key) {
  if (key.match(publicKeyPemMatcher) || key.includes(publicKeyX509CertMatcher)) {
    throw new TokenError(..., 'Public keys are not supported for signing.')
  }
  const pemData = key.trim().match(privateKeyPemMatcher)
  if (!pemData) {
    return 'HS256'
  }
  // ...
}
```

`key.trim().match(privateKeyPemMatcher)`：前导空白不影响「这是不是私钥 PEM」。公钥函数对 `publicKeyPemMatcher` **没有**对应的 `trim`。

V1 等于在公钥入口用了更脆的 `^`，而同文件已经证明 PEM 分类应该在 trim 之后做。不是仓库里没有更好的谓词，是 **公钥路径没用**。

6.2.0 把 trim 提到 `performDetectPublicKeyAlgorithms` 第一行，并单独认出 PKCS1（`publicKeyPemMatch[1] === 'RSA'` → 直接 `rsaAlgorithms`，不再误走 SPKI decode）。那是把私钥路径的习惯真正接到公钥上。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs HMAC」落到具体代码：

- `key.match(/^-----BEGIN( RSA)? PUBLIC KEY-----/)`：看**第一个字符**是不是 `-`
- `createHmac(alg, key)`：看整串字节

只要构造一种输入，使「行首不是 PEM 头」但「去掉空白后仍是同一把 RSA 公钥」，第一行当 HMAC，第二行用这串当 secret。

`"\n" + PUB` 就是这样来的：

```text
key[0] = '\n'
^-----BEGIN...  失败
非证书 → return hsAlgorithms
攻击者 HMAC-SHA256(key=\n+PUB, message)
verifier 用同一 key 验过 → role=admin → flag
```

字符串变换只有一个前导换行。PEM 体未改。V1 正则比「这是不是 PEM」窄：它要求 PEM 头贴在左缘。数据库、环境变量、编辑器保存经常在 PEM 前留一行空行——GHSA 写的就是 `'\\n' + publicKeyPem`。

对干净 seed：`^` 命中 → 不进 HMAC（随后 SPKI decode 失败 → 401）。对残余：`^` 不命中 → 进 HMAC（200）。同一把密钥，只差一个换行。

---

## 残余仍然走同一条 verify 分类（CVE-2026-34950）

没有换路由语义、没有换 HS256、没有换 payload。还是：

```http
GET /admin-tainted
Authorization: Bearer <HS256, secret="\n"+PUB, role=admin>
```

`performDetectPublicKeyAlgorithms` 仍然用同一个 `publicKeyPemMatcher`。V1 那一行 `^` 照样执行；对带 `\n` 的 key 它失败；函数返回 `hsAlgorithms`；`verifySignature` 用带换行的串做 HMAC；flag 出现在 JSON。

本 case heldout 把 secret 写死为 `("\n" + pub).encode("utf-8")`，打 `/admin-tainted`。认证：v1 + `--residual` 退出码 0。平台 residual 与链是同一 sink（密钥分类 → HMAC verify），只是 verifier 的 key 带空白；seed 走 `/admin`（干净 key）是为了让 V1 对「无空白 PKCS1」呈 401。

---

## 后来又补了什么（CVE-2026-34950，fast-jwt 6.2.0）

tag `v6.2.0`：

```javascript
function performDetectPublicKeyAlgorithms(key) {
  const trimmedKey = key.trim()
  const publicKeyPemMatch = trimmedKey.match(publicKeyPemMatcher)

  if (trimmedKey.match(privateKeyPemMatcher)) {
    throw new TokenError(..., 'Private keys are not supported for verifying.')
  } else if (publicKeyPemMatch && publicKeyPemMatch[1] === 'RSA') {
    return rsaAlgorithms
  } else if (!publicKeyPemMatch && !trimmedKey.includes(publicKeyX509CertMatcher)) {
    return hsAlgorithms
  }
  // ... SPKI / 证书 ...
}
```

对残余：`trim()` 吃掉 `\n`，正则命中，捕获组 `' RSA'`（注意 6.2.0 正则是 `/^-----BEGIN(?: (RSA))? PUBLIC KEY-----/`，组 1 为 `'RSA'`）→ 直接 `rsaAlgorithms` → HS256 不在列表里 → 401 `The token algorithm is invalid.`。干净 PKCS1 也走这条，不再依赖 SPKI decode 失败当安全。Snyk SNYK-JS-FASTJWT-15876721：升级到 6.2.0。

即便如此，分类仍是「看 PEM 头长什么样」，不是「用 crypto 模块问这把 key 的 type」。对已知空白前缀链它够用。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是匹配器的写法（includes → `^` 正则），为了认 PKCS1 头。真正放行 HS256 的是「match 失败则当 secret」。V2 仍在同一层加码（trim），但顺手把 PKCS1 收成 `rsaAlgorithms`，不再靠 decode 抛错。

**不是没有更好的谓词。**  
私钥路径已经 `trim().match(...)`。公钥在 3.3.2 对同一类 PEM 头不做 trim。从 V1 的 diff 只能看到正则变了；要判断补丁是否闭合，必须看到 match 失败时的默认分支是 HMAC，以及私钥路径已经 trim。

**同一函数、同一 `key`，只换了左缘空白。**  
任何把「数据库里的 PEM」交给 `createVerifier({ key })` 且不锁 algorithms 的部署，在 3.3.2 上都吃这个 `^`。

**失败默认是 HMAC，不是拒绝。**  
「认不出 PEM」被设计成「那就是共享密钥」。安全分类里这是一条很宽的默认。空白、BOM、`BEGIN RSA PUBLIC KEY` 的空格差异，都会把非对称密钥推进这条默认。

**金丝雀在 admin JSON 里是有意的。**  
flag 只在 verify 成功且 `role=admin` 时出现。能读到它，说明 HS256 真的用公钥字节验过，而不是路由忘了鉴权。

---

## 版本、入口、参考

| | npm | `publicKeyPemMatcher` | 公钥 `trim` | 干净 PKCS1 HS256 seed | `\n`+PKCS1 residual |
|---|---|---|---|---|---|
| V0 | 3.3.1 | `'-----BEGIN PUBLIC KEY-----'` + includes | 无 | 当 HMAC，200 flag | 当 HMAC |
| V1 | 3.3.2 | `/^-----BEGIN( RSA)? PUBLIC KEY-----/` | 无 | decode 失败 401 | `^` 失败 → HMAC，200 flag |
| V2 | 6.2.0 | 同类正则 | `trimmedKey = key.trim()` 且 PKCS1 → rsa | 401 | trim 后当 RSA，401 |

- Web：`GET /admin`（干净 key）、`GET /admin-tainted`（`\n`+key）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2023-48223](https://nvd.nist.gov/vuln/detail/CVE-2023-48223)、[GHSA-c2ff-88x2-x9pg](https://github.com/nearform/fast-jwt/security/advisories/GHSA-c2ff-88x2-x9pg)
- [CVE-2026-34950](https://nvd.nist.gov/vuln/detail/CVE-2026-34950)、[GHSA-mvf2-f6gm-w987](https://github.com/nearform/fast-jwt/security/advisories/GHSA-mvf2-f6gm-w987)
- V1 commit：[15a6e92](https://github.com/nearform/fast-jwt/commit/15a6e92)
- 源码：`https://github.com/nearform/fast-jwt/blob/v3.3.2/src/crypto.js`、`.../blob/v6.2.0/src/crypto.js`
