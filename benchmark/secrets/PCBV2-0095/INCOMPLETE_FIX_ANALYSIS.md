# DataEase 2.10.23：主站 JWT 密钥改成生成值了，分享链接仍用 `link-pwd-fit2cloud`

- Case：`PCBV2-0095`（`dataease-cve-2026-57172`）
- 产品：DataEase。本 case 用官方镜像 `dataease:v2.10.1` / `v2.10.23` / `v2.10.24` + MySQL + Redis，真实 `POST /de2api/dataVisualization/findById`。
- 链：CVE-2024-52295（<2.10.2 → 2.10.2，commit `e755248`，GHSA-45v9-gfcv-xcq6）→ CVE-2026-57172（<2.10.24 → 2.10.24，commit `356e83b`，GHSA-7cpg-f4cj-7pgm）
- 源码对着 tag `v2.10.23` 的 `ShareSecretManage.java`（`getSecret`、`defaultPwd`）和 `sdk/common/.../auth/filter/TokenFilter.java`（`X-DE-LINK-TOKEN` 分支）。V2 对着 2.10.24 的 `loadOrGenerateSecret`。运行时是官方镜像整包。

2024 年 11 月，CVE-2024-52295 修的是 **主登录 JWT**：`SubstituleLoginServer` / `SubstituleLoginConfig.tokenSecret` 把密钥写死成 `83d923c9f1d8fcaa46cae0ed2aaa81b5`，uid/oid 也写死为 1。2.10.2 改成生成并持久化随机密钥，CommunityTokenFilter 按生成密钥验 `X-DE-TOKEN`。两年后 GHSA-7cpg-f4cj-7pgm 写明：*CVE-2024-52295 has fixed the similar issue of SubstituleLoginConfig.tokenSecret, but ShareSecretManage.defaultPwd continues to use the same anti-pattern, constituting an incomplete fix for CVE-2024-52295.* 无密码分享的 HMAC 密钥默认仍是源码里的 `link-pwd-fit2cloud`。

根因不只是「又硬编码了一个字符串」。检查（主站验签）换了密钥来源；分享链的签发和校验仍读同一 `@Value` 默认值。下面按 TokenFilter 的两个 header 走进去、2.10.23 的 `getSecret` 在 pwd 为空时返回什么、谁用这个返回值做 HMAC256、2.10.2 已经用过的 `generateSecret` 有没有接到分享侧，把这几层写完。

---

## 这块功能本来在干什么

DataEase 有两套 HMAC-JWT：

| Header | 用途 | 2.10.23 的密钥从哪来 |
|---|---|---|
| `X-DE-TOKEN` | 主站登录 | 生成后的 substitute/community 密钥（CVE-2024-52295 之后） |
| `X-DE-LINK-TOKEN` | 分享链接（可无密码） | `ShareSecretManage.getSecret(resourceId, uid)` |

无密码分享时，签发侧 `LinkTokenUtil.generate(uid, resourceId, exp, secret, oid)` 用 `HMAC256(pwd)`，claims 含 `uid` / `resourceId` / `oid`。校验侧 TokenFilter 用同一 secret `verifier.verify(linkToken)`，通过则 `UserUtils.setUserInfo(uid, oid)`，后续 `@DeLinkPermit` 接口把调用者当成分享创建者。

本 case 的受保护接口：

```http
POST /de2api/dataVisualization/findById
{"id": 777000777, "busiFlag": "dashboard"}
```

仪表盘 `name` 被种子成 `${PCB_FLAG}`。能 200 且 body 含 flag，说明 **验签接受了伪造 token，并以分享者身份读到了行**。flag 不在 JWT 里。

数据流：

```text
HTTP X-DE-LINK-TOKEN
    → TokenFilter.doFilter
         JWT.decode（先不验签）→ uid, oid, resourceId
         shareSecretManage.getSecret(resourceId, uid)
              SELECT xpack_share WHERE creator=uid AND resource_id=...
              若 pwd 非空：用分享密码
              否则：defaultPwd                         ← V1 硬编码默认
         HMAC256(linkSecret).verify(token)
         setUserInfo(uid, oid)
    → findById @DeLinkPermit
         返回 visualization VO（name = flag）
```

主站路径是另一条：`ServletUtils.getToken()` → `TokenUtils.validate` → 生成密钥。seed 走这条；residual 走 linkToken 这条。

---

## 原始漏洞：主站硬编码 HMAC 密钥（CVE-2024-52295，2.10.1）

GHSA-45v9-gfcv-xcq6 给出的签发代码：

```java
String md5Pwd = "83d923c9f1d8fcaa46cae0ed2aaa81b5";
tokenUserBO.setUserId(1L);
tokenUserBO.setDefaultOid(1L);
return generate(tokenUserBO, md5Pwd);  // HMAC256(secret) + uid/oid
```

任何人都能离线签出管理员 `X-DE-TOKEN`。NVD：*The JWT secret is hardcoded in the code, and the UID and OID are hardcoded. The vulnerability has been fixed in v2.10.2.*

本 case 的 v0=2.10.1。community core 在这个版本上对主站 JWT **甚至还不做**与生成密钥对等的校验（审计：wrong-key 也 200）。seed 用 `83d923...` 伪造 `X-DE-TOKEN`，`findById` 返回 flag。v0 + `--seed` 退出码 0。

这是 **主站 header** 上的硬编码密钥。V1（2.10.23）已包含 2.10.2 起的主站修复，所以同一 seed 在 V1 上 401。

---

## 维护者改了什么（CVE-2024-52295 修复，进 2.10.2 / 本 case V1=2.10.23）

commit `e755248d59543bcd668ace495f293ff735fa82e9` 去掉硬编码 `tokenSecret`，改为 `generateSecret()` 并写入 `substitule.json`（后续 community 路径用 md5(配置密码)/生成密钥验 `X-DE-TOKEN`）。2.10.23 上用 `83d923...` 签的主站 token：`TokenUtils.validate` / CommunityTokenFilter 失败，401 `signature-invalid`。v1 + `--seed` 退出码 10。

**同一份 2.10.23 源码**里，分享密钥仍是：

```java
# ShareSecretManage.java  (v2.10.23)
@Component("shareSecretManage")
public class ShareSecretManage {

    @Getter
    @Value("${dataease.default-link-pwd:link-pwd-fit2cloud}")
    private String defaultPwd;

    public String getSecret(Long resourceId, Long uid) {
        QueryWrapper<XpackShare> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("creator", uid);
        queryWrapper.eq("resource_id", resourceId);
        XpackShare xpackShare = xpackShareMapper.selectOne(queryWrapper);
        if (ObjectUtils.isEmpty(xpackShare)) DEException.throwException("Share resource do not exist");
        String sharePwd = xpackShare.getPwd();
        return StringUtils.isNotBlank(sharePwd) ? sharePwd : defaultPwd;
    }
}
```

冒号后面是 Spring 在配置缺失时的默认值。官方镜像的 `application.yml` 通常不设 `dataease.default-link-pwd`，于是每个安装的无密码分享都用同一串 `link-pwd-fit2cloud`。

补丁默认：硬编码 HMAC 密钥只存在于 substitute 登录。分享链是「用户设的密码」或「一个无害的默认口令」，没有被当成与 52295 同类的信任根。

---

## 检查之后谁真正消费那个值

TokenFilter 在白名单和桌面模式之后：

```java
# TokenFilter.java :: doFilter  (v2.10.23)
            String linkToken = ServletUtils.getHead(AuthConstant.LINK_TOKEN_KEY);
            if (StringUtils.isNotBlank(linkToken)) {
                if (StringUtils.length(linkToken) < 100) {
                    DEException.throwException("token is invalid");
                }
                DecodedJWT jwt = JWT.decode(linkToken);
                Long userId = jwt.getClaim("uid").asLong();
                Long oid = jwt.getClaim("oid").asLong();
                Long resourceId = jwt.getClaim("resourceId").asLong();
                ...
                Object pwdObj = ReflectionUtils.invokeMethod(getSecretMethod,
                    shareSecretManage, resourceId, userId);
                String linkSecret = pwdObj.toString();

                Algorithm algorithm = Algorithm.HMAC256(linkSecret);
                JWTVerifier verifier = JWT.require(algorithm).build();
                algorithm.verify(decode);
                verifier.verify(linkToken);

                UserUtils.setUserInfo(new TokenUserBO(userId, oid));
                filterChain.doFilter(servletRequest, servletResponse);
                return;
            }
            String token = ServletUtils.getToken();
            TokenUserBO userBO = TokenUtils.validate(token);
```

顺序是固定的：

1. **先 decode**，从攻击者可控的 JWT 里取出 uid / resourceId（尚未验签）。
2. 用这对主键去库里找分享行，取出 `getSecret` 的返回值。
3. **再用这个返回值验签**。

无密码分享（`pwd` NULL）时第 2 步得到的就是全世界相同的 `link-pwd-fit2cloud`。攻击者只要知道（或猜到）一组真实的 `(uid, resourceId, oid)`——本 case 种子为 admin uid=1、resource 777000777、oid=1——就能离线 HMAC256 签出通过第 3 步的 token。

主站路径不会读 `defaultPwd`。Community 验签用的生成密钥挡得住 `83d923...`；它从不挡 `X-DE-LINK-TOKEN`。

`findById` 消费的是 Filter 放进 `UserUtils` 的身份，以及 body 里的 id。签名通过后，VO 的 `name` 就是 flag。

---

## 仓库里已经有「生成并持久化密钥」的做法，分享侧没用

CVE-2024-52295 的修复已经实现了：`SecureRandom` → Base64 → 写到安装目录 JSON，启动时读回，配置项可覆盖。GHSA-7cpg 把这称为对 `tokenSecret` 的修复。`ShareSecretManage` 在 2.10.23 仍然只有 `@Value` 默认字符串，没有 `@PostConstruct`、没有文件、没有 `SecureRandom`。

签发侧 `XpackShareManage` 与校验侧对称（GHSA 引用的 `LinkTokenUtil.generate`）：

```java
# LinkTokenUtil.java :: generate  (v2.10.23)
public static String generate(Long uid, Long resourceId, Long exp, String pwd, Long oid) {
    Algorithm algorithm = Algorithm.HMAC256(pwd);
    JWTCreator.Builder builder = JWT.create();
    builder.withClaim("uid", uid).withClaim("resourceId", resourceId).withClaim("oid", oid);
    if (ObjectUtils.isNotEmpty(exp) && !exp.equals(0L)) {
        builder = builder.withExpiresAt(new Date(exp));
    }
    return builder.sign(algorithm);
}
```

```text
secret = blank(share.pwd) ? shareSecretManage.getDefaultPwd() : share.pwd
LinkTokenUtil.generate(uid, resourceId, exp, secret, oid)
```

同一默认值既用于签发也用于校验。把默认值写进 git，等于把所有无密码分享的 HMAC 密钥写进 git。攻击者不必截获曾经签发过的 token：只要知道 `(uid, resourceId, oid)` 三元组，就能自己签一个新的、甚至把 `exp` 拉得很长。advisory 还指出原分享被撤销之后，若库里仍能按 (creator, resource_id) 命中一行且 pwd 仍空，伪造 token 继续过 Filter——撤销没有旋转密钥。

2.10.24 几乎是把 52295 那套 `loadOrGenerateSecret` 抄到分享模块（`share-secret.json`，键名 `linkPwd`）。不是 2.10.23 里做不到，是 **只对主站做了**。

---

## 这个补丁挡住了什么、没挡住什么

- 主站：`X-DE-TOKEN` 必须用安装后生成的密钥签；源码里的 `83d923...` 不再能过
- 分享：无密码行的 HMAC 密钥仍是源码默认值 `link-pwd-fit2cloud`

字符串变换是 **换 header、换密钥、同一 HMAC 算法、同一受保护 API**：

```text
seed:     X-DE-TOKEN      HMAC256("83d923c9f1d8fcaa46cae0ed2aaa81b5")  uid=1,oid=1
          V1：验签失败 401

residual: X-DE-LINK-TOKEN HMAC256("link-pwd-fit2cloud")
          claims: uid=1, resourceId=777000777, oid=1
          V1：getSecret → defaultPwd → 验签成功 200 + flag
```

没有绕过 HMAC、没有改算法、没有打未授权的 id 枚举。种子提供了密码为空的 `xpack_share` 行，使 `getSecret` 走到默认分支——这是产品默认的无密码分享，不是测试特供逻辑。

seed 被挡住只说明「主站硬编码密钥失效」，不说明「所有 HMAC-JWT 都改用了每安装随机密钥」。

---

## 残余走的是兄弟 header / 兄弟密钥，同一 findById（CVE-2026-57172）

平台 verify 的 residual 打 `X-DE-LINK-TOKEN` + `findById`，seed 打 `X-DE-TOKEN` + 同一 `findById`。效果通道相同（200 body 含仪表盘 name=flag）；密码学信任根不同。heldout 与 GHSA 一致：不完整修复是 **同一反模式落在分享模块**，不是主站验签被绕过。

v1 + `--residual`：HTTP 200，`data.name` 为 flag。v2：同一伪造 token 401（安装时生成的密钥对不上）。错密钥 401、真生成密钥 200 的对照说明闭合是密钥特定的，不是接口被关掉。

若分享设了自定义密码，`getSecret` 返回该密码而不是 defaultPwd，本 residual 的已知字符串会失败——那是另一条配置。产品默认允许无密码分享，advisory 攻击面就是这条默认。

---

## 后来又补了什么（CVE-2026-57172，2.10.24）

commit `356e83b518603f5612104760ced80aae8fc5d675`（本仓库 patch.diff 即 2.10.23→2.10.24 的 `ShareSecretManage`）：

- `@Value("${dataease.default-link-pwd:}")` —— 不再把 `link-pwd-fit2cloud` 当默认
- `@PostConstruct`：若管理员显式配置了 `configuredPwd` 则用之，否则 `loadOrGenerateSecret()`
- `SecureRandom` 32 字节 Base64，写入 `/opt/dataease2.0/conf/share-secret.json`

伪造 token 用源码里的旧默认值验签失败。NVD：*This issue is fixed in version 2.10.24.*

2.10.24 同一天还有其它分享相关 advisory（例如 proxyInfo 过早返回 linkToken）。本 case 的 v2 关闭的是硬编码 defaultPwd 这一条。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们换了主站 JWT 的密钥材料。TokenFilter 里并列的 linkToken 分支仍向 `getSecret` 要密钥，而 `getSecret` 在无密码时返回编译进镜像的字符串。V2 把「生成并落盘」接到这个返回值上。

**不是没有现成实现。**  
`generateSecret` + JSON 文件是 2.10.2 已经为 substitute 写过的。分享模块直到 2.10.24 才复制。

**先 decode 再查库再验签。**  
resourceId/uid 来自未验签 JWT。密钥若可预测，这就是完整的伪造。密钥若是每安装随机，没有读到 `share-secret.json` 就签不出。

**`@Value` 默认值等于把密钥签进 git。**  
配置项本意是「可覆盖」；未覆盖时的默认值成了全球共享 HMAC 密钥。52295 的 `83d923...` 是同一反模式。

**金丝雀是授权种子。**  
flag 在 `data_visualization_info.name`。能读到它证明 Filter 接受了伪造身份，而不是 SQL 里碰巧有公开查询。

---

## 版本、入口、参考

| | 版本 | `X-DE-TOKEN` 密钥 | `X-DE-LINK-TOKEN` 无密码密钥 | seed 主站伪造 | residual 分享伪造 |
|---|---|---|---|---|---|
| V0 | 2.10.1 | 硬编码 `83d923...`（且 community 核验弱） | 同默认分享密钥 | 200 + flag | （不必） |
| V1 | 2.10.23 | 生成密钥，硬编码主站 token 401 | **仍 `link-pwd-fit2cloud`** | 401 | 200 + flag |
| V2 | 2.10.24 | 同 V1 | 每安装随机，持久化 share-secret.json | 401 | 401 |

- Web：`POST /de2api/dataVisualization/findById`；header `X-DE-TOKEN` 或 `X-DE-LINK-TOKEN`
- 认证：同一受保护接口；V1 关闭主站硬编码密钥；V1 分享硬编码密钥仍通；V2 关闭
- [CVE-2024-52295](https://nvd.nist.gov/vuln/detail/CVE-2024-52295)、[CVE-2026-57172](https://nvd.nist.gov/vuln/detail/CVE-2026-57172)
- [GHSA-45v9-gfcv-xcq6](https://github.com/dataease/dataease/security/advisories/GHSA-45v9-gfcv-xcq6)、[GHSA-7cpg-f4cj-7pgm](https://github.com/dataease/dataease/security/advisories/GHSA-7cpg-f4cj-7pgm)
- V1：[ShareSecretManage.java @ v2.10.23](https://github.com/dataease/dataease/blob/v2.10.23/core/core-backend/src/main/java/io/dataease/share/manage/ShareSecretManage.java)、[TokenFilter.java @ v2.10.23](https://github.com/dataease/dataease/blob/v2.10.23/sdk/common/src/main/java/io/dataease/auth/filter/TokenFilter.java)
- V2：[commit 356e83b](https://github.com/dataease/dataease/commit/356e83b518603f5612104760ced80aae8fc5d675)
