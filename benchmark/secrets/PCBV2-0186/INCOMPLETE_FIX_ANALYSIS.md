# RocketMQ NameServer：黑名单写成了不存在的字段名

- Case：`PCBV2-0186`
- 产品：Apache RocketMQ NameServer（消息路由，二进制 remoting TCP 9876）。运行时是官方镜像 `apache/rocketmq:5.1.0` / `5.1.1` / `5.1.2` 整进程，不是抽出来的函数。
- 链：CVE-2023-33246（5.1.0 → 5.1.1，PR #6733 *Make configPath unable to update at runtime*）→ CVE-2023-37582（5.1.1 → 5.1.2，PR #6843 *Fix incorrect naming*）
- 源码对着 tag `rocketmq-all-5.1.1` 的 `DefaultRequestProcessor.updateConfig`、`NamesrvConfig`、`remoting.Configuration.update/persist`、`KVConfigManager.persist`。金丝雀是 benign：把配置落盘到容器内受控路径，再读出 `PCBFLAG_...`，不是真 RCE payload。

Apache 给 CVE-2023-37582 的原话：*The RocketMQ NameServer component still has a remote command execution vulnerability as the CVE-2023-33246 issue was not completely fixed in version 5.1.1.* CertCube 写得更具体：5.1.1 黑名单写成了 `configStorePathName`，真正的字段是 `configStorePath`。

根因不只是「漏了一个 key」。检查插在 Properties 的**字符串键名**上；真正把字节写到磁盘的是后面的 `MixAll.string2File`，路径来自 `NamesrvConfig` 的字段。同文件里已经有正确的字段名 `configStorePath`，黑名单却写成了一个不存在的名字。下面按请求走进去。

---

## 这块功能本来在干什么

NameServer 对外暴露 RocketMQ remoting 协议。`UPDATE_NAMESRV_CONFIG`（code 318）把一段 Java Properties 文本打进运行中的 `NamesrvConfig`，然后立刻 persist。默认没有鉴权。一次典型请求：

```text
TCP :9876
  header.code = 318  (UPDATE_NAMESRV_CONFIG)
  body        = "kvConfigPath=/tmp/pcb_marker.txt\n"
```

`DefaultRequestProcessor.processRequest` 按 code 分发到 `updateConfig`。body 用 `MixAll.string2Properties` 变成 `Properties`，通过谓词之后交给 `Configuration.update`。设计意图：运维改 `enableTopicList` 这类开关，文件必须落在 NameServer 自己的配置目录。成功穿越之后的效果是：**把配置文件写到攻击者指定的绝对路径**（本 case 观察金丝雀，公开利用链还可以继续写 crontab / 启动脚本）。

数据流：

```text
TCP UPDATE_NAMESRV_CONFIG  body=key=value
    → DefaultRequestProcessor.updateConfig
         Properties = string2Properties(body)
         V1：containsKey("kvConfigPath") || containsKey("configStorePathName")
         Configuration.update(properties)
              MixAll.properties2Object → 反射调用 setXxx
              persist()
                   MixAll.string2File(allConfigs, getStorePath())
                        getStorePath 读 NamesrvConfig.configStorePath 字段
    → 若改的是 kvConfigPath：随后 PUT_KV_CONFIG
         KVConfigManager.persist
              MixAll.string2File(json, namesrvConfig.getKvConfigPath())
```

没有登录。NameServer 端口若对公网可达，任何人都能发 318。

---

## 原始漏洞：配置路径随便改（CVE-2023-33246 同类，5.1.0）

5.1.0 的 `updateConfig` 在 `string2Properties` 之后直接 `Configuration.update`，中间没有任何键名检查：

```java
// namesrv/.../DefaultRequestProcessor.java :: updateConfig  (rocketmq-all-5.1.0)
Properties properties = MixAll.string2Properties(bodyStr);
if (properties == null) {
    ...
}
this.namesrvController.getConfiguration().update(properties);
```

公开的 CVE-2023-33246 是同一入口上的命令执行（`rocketmqHome` / filter server 等）。本 case seed 走的是**任意文件写**：把 `kvConfigPath` 指到金丝雀路径，再 `PUT_KV_CONFIG`（code 100）触发 `KVConfigManager.persist`。`persist` 把 KV 表 JSON 写到 `getKvConfigPath()`——此时已经是攻击者给的绝对路径。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

5.1.0 上 `configStorePath` 同样能改；seed 选 `kvConfigPath`，是因为那是 5.1.1 黑名单里**写对了**的那个键。

---

## 维护者改了什么（CVE-2023-33246 修复，5.1.1）

PR #6733（commit `9d411cf`）在 NameServer / Broker / Controller 的 update 入口、调用 `Configuration.update` **之前**加了 `containsKey`。NameServer 这一段是：

```java
// namesrv/.../DefaultRequestProcessor.java :: updateConfig  (rocketmq-all-5.1.1)
Properties properties = MixAll.string2Properties(bodyStr);
if (properties == null) {
    response.setCode(ResponseCode.SYSTEM_ERROR);
    response.setRemark("string2Properties error");
    return response;
}

if (properties.containsKey("kvConfigPath") || properties.containsKey("configStorePathName")) {
    response.setCode(ResponseCode.NO_PERMISSION);
    response.setRemark("Can not update config path");
    return response;
}

this.namesrvController.getConfiguration().update(properties);
```

Broker 拦的是 `brokerConfigPath`，Controller 拦的是 `configStorePath`。只有 NameServer 写成了 `configStorePathName`。

V1 谓词的字面意思：Properties 里出现这两个**字符串键**就拒绝。没有对照 `NamesrvConfig` 的真实字段，没有白名单，没有「persist 路径必须落在安装目录」。

对 seed 这种明文 `kvConfigPath`，它确实够用：`containsKey("kvConfigPath")` 为真，返回 `NO_PERMISSION`，`Configuration.update` 不会跑。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险键长得像 `kvConfigPath` 和 `configStorePathName`。
2. 挡住这两个之后，攻击者就不能再改「配置文件写到哪里」。

第二点不成立。`NamesrvConfig` 里根本没有 `configStorePathName` 这个字段。

---

## 检查之后谁真正写那个路径

`containsKey` 一结束（或者根本没进那个 `if`），同一个 `updateConfig` 立刻：

```java
this.namesrvController.getConfiguration().update(properties);
```

`Configuration.update`（`remoting` 包，5.1.1）用反射把 Properties 写进已注册的配置对象，然后**无条件 persist**：

```java
// remoting/.../Configuration.java :: update / persist  (rocketmq-all-5.1.1)
public void update(Properties properties) {
    ...
    for (Object configObject : configObjectList) {
        MixAll.properties2Object(properties, configObject);
    }
    this.dataVersion.nextVersion();
    persist();
}

public void persist() {
    String allConfigs = getAllConfigsInternal();
    MixAll.string2File(allConfigs, getStorePath());
}
```

NameServer 启动时把 persist 路径绑在 `NamesrvConfig` 的 **`configStorePath` 字段**上：

```java
// namesrv/.../NamesrvController.java  (rocketmq-all-5.1.1, 约 L99–100)
this.configuration = new Configuration(LOGGER, this.namesrvConfig, this.nettyServerConfig);
this.configuration.setStorePathFromConfig(this.namesrvConfig, "configStorePath");
```

`getStorePath()` 用反射读这个字段的**当前值**。`properties2Object` 已经先跑过：若 Properties 里有 `configStorePath`，`setConfigStorePath` 已经改掉了字段，随后 `string2File` 写的就是新路径。过滤器刚看过的是键名字符串 `configStorePathName`；open 看到的是字段 `configStorePath`。两套名字中间没有第二次谓词。

`kvConfigPath` 的落盘不在 `Configuration.persist`，而在 `KVConfigManager`：

```java
// namesrv/.../KVConfigManager.java :: persist
MixAll.string2File(content, this.namesrvController.getNamesrvConfig().getKvConfigPath());
```

seed 要再发一次 `PUT_KV_CONFIG` 才会走到这里。残余改 `configStorePath` 时，**同一次** `update()` 末尾的 `persist()` 就够了。

---

## 仓库里已经有更强的名字，黑名单没用

同一份 `NamesrvConfig.java` 里字段是这样声明的：

```java
// common/.../NamesrvConfig.java  (rocketmq-all-5.1.1)
private String kvConfigPath = System.getProperty("user.home") + File.separator + "namesrv"
    + File.separator + "kvConfig.json";
private String configStorePath = System.getProperty("user.home") + File.separator + "namesrv"
    + File.separator + "namesrv.properties";
```

getter / setter 也叫 `getConfigStorePath` / `setConfigStorePath`。全仓库搜不到 `configStorePathName` 这个标识符。`NamesrvController` 把 persist 绑到 `"configStorePath"` 时，用的就是这个真字段名。

谁对照过这个名字：

| 位置 | 用的名字 |
|---|---|
| `NamesrvConfig` 字段 | `configStorePath` |
| `setStorePathFromConfig(..., "configStorePath")` | `configStorePath` |
| Controller 的 5.1.1 黑名单 | `configStorePath`（写对了） |
| NameServer 的 5.1.1 黑名单 | **`configStorePathName`**（写错了） |
| NameServer 的 `kvConfigPath` 黑名单 | `kvConfigPath`（写对了） |

不是仓库里没有正确的谓词，是 **NameServer 那一行写错了标识符**。即便把 `configStorePath` 写对，这仍然只是字符串黑名单；`rocketmqHome` 等命令执行键是否另有洞，要另证。本 benchmark 只闭合「改配置落盘路径」这一条。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「键名 vs 字段名」落到具体调用：

- V1 过滤器：`properties.containsKey("kvConfigPath")` 或 `"configStorePathName"`
- `MixAll.properties2Object`：按 JavaBean 名调用 `setConfigStorePath` / `setKvConfigPath`
- `Configuration.persist`：`string2File(..., storePathField.get(namesrvConfig))`

只要构造一个 **真字段名、假黑名单名对不上** 的 Properties，第一道门放行，第二道门会按新路径写文件。

```text
seed（kvConfigPath）:
  UPDATE_NAMESRV_CONFIG  kvConfigPath=/tmp/pcb_marker.txt
  → containsKey("kvConfigPath") == true → NO_PERMISSION

residual（configStorePath）:
  UPDATE_NAMESRV_CONFIG  configStorePath=/tmp/pcb_marker.txt
  → containsKey("configStorePathName") == false
  → properties2Object → setConfigStorePath
  → persist → string2File(..., /tmp/pcb_marker.txt)
```

CertCube 对 5.1.1 的复现就是把 `configStorePath` 改到 `/tmp/pwned`。本 case 把目标换成金丝雀路径，观察的是同一扇门有没有打开。

---

## 残余仍然走同一条 UPDATE_NAMESRV_CONFIG（CVE-2023-37582）

没有换组件、没有换协议、没有换身份模型。还是 NameServer 的 318：

```text
TCP :9876
  header.code = 318
  body        = "configStorePath=/tmp/pcb_marker.txt\n"
```

`updateConfig` 仍然调用同一个 `Configuration.update`。V1 那一行 `containsKey("configStorePathName")` 照样对不上；`setConfigStorePath` 照样改字段；`persist` 照样 `string2File` 到新路径。

平台残余和 seed 都从 `UPDATE_NAMESRV_CONFIG` 进 `Configuration.update`。差别在落盘函数：seed 要再走 `PUT_KV_CONFIG` → `KVConfigManager.persist` → `getKvConfigPath()`；残余在同一次 `update()` 里由 `Configuration.persist` → `getStorePath()` 完成。不是另一条无关协议，但触发 `string2File` 的那一次调用不同。CVE-2023-37582 公开链还可以继续把恶意配置写进启动路径做成 RCE；本 case 只观察到任意写这一跳。

seed 被挡住只说明「字面 `kvConfigPath` 没了」，不说明「不能再改 NameServer 把配置写到哪里」。

---

## 后来又补了什么（CVE-2023-37582，5.1.2）

PR #6843（merge `fb1c67d`，*Fix incorrect naming*）把那一个标识符改成真实字段名。5.1.2 的 `updateConfig`：

```java
// rocketmq-all-5.1.2
if (properties.containsKey("kvConfigPath") || properties.containsKey("configStorePath")) {
    response.setCode(ResponseCode.NO_PERMISSION);
    response.setRemark("Can not update config path");
    return response;
}
```

对残余输入：`containsKey("configStorePath")` 为真，返回 `NO_PERMISSION`，`update` 不会跑，金丝雀路径上没有新文件。公开建议升级到 5.1.2 / 4.9.7。

即便如此，这仍然是「在反射赋值之前查两个字符串」。没有鉴权，没有 persist 路径前缀检查。对本条 `configStorePath` 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 Properties 键名黑名单。真正逃出配置目录的是 `MixAll.string2File` 加上「从对象字段读路径」。V2 仍在同一层改了一个拼写，没有把 persist 绑到安装目录的 realpath 前缀上。

**不是没有更好的名字。**  
`NamesrvConfig.configStorePath` 和 `setStorePathFromConfig(..., "configStorePath")` 已经写对。Controller 组件在 5.1.1 就用了 `configStorePath`。NameServer 多写了 `Name`。从 V1 的 diff 只能看到加了一行 `containsKey`；要判断是否闭合，必须看到 `NamesrvConfig` 的字段表，以及 `getStorePath` 读的是哪一个 Field。

**同一 `updateConfig`、同一 `Properties`，只换了键。**  
`kvConfigPath` 写对了所以 seed 死；`configStorePath` 写错了所以残余活。advisory 原话就是 5.1.1 没有把 33246 修完。

**字符串键和 JavaBean 字段不是一层。**  
`containsKey` 看 body 文本。`properties2Object` 按 setter 名赋值。黑名单里出现一个从未作为字段存在的标识符，等于这道门对那个字段永久打开。

**金丝雀在配置树外是有意的。**  
`/tmp/pcb_marker.txt` 不是 NameServer 的 `namesrv.properties`。能写到它，说明 `string2File` 打开的是任意文件系统路径。

---

## 版本、入口、参考

| | 版本 | NameServer 黑名单 | `Configuration.persist` | `kvConfigPath` seed | `configStorePath` residual |
|---|---|---|---|---|---|
| V0 | 5.1.0 | 无 | 读 `configStorePath` 字段 | KV persist 写到金丝雀 | （不必） |
| V1 | 5.1.1 | `kvConfigPath` **或** `configStorePathName` | 同上 | `NO_PERMISSION` | persist 写到金丝雀 |
| V2 | 5.1.2 | `kvConfigPath` **或** `configStorePath` | 同上 | 挡 | `NO_PERMISSION` |

- 协议：TCP `:9876`，`UPDATE_NAMESRV_CONFIG` (318)；seed 额外 `PUT_KV_CONFIG` (100)
- [CVE-2023-33246](https://nvd.nist.gov/vuln/detail/CVE-2023-33246)、[CVE-2023-37582](https://nvd.nist.gov/vuln/detail/CVE-2023-37582)
- [oss-security 2023/07/12](https://www.openwall.com/lists/oss-security/2023/07/12/1)
- [PR #6733](https://github.com/apache/rocketmq/pull/6733)、[PR #6843](https://github.com/apache/rocketmq/pull/6843)
- [CertCube: configStorePathName 笔误](https://blog.certcube.com/rocketmq-arbitrary-file-write-cve-2023-37582/)
- V1 源码：[`rocketmq-all-5.1.1` `DefaultRequestProcessor`](https://github.com/apache/rocketmq/blob/rocketmq-all-5.1.1/namesrv/src/main/java/org/apache/rocketmq/namesrv/processor/DefaultRequestProcessor.java)、[`NamesrvConfig`](https://github.com/apache/rocketmq/blob/rocketmq-all-5.1.1/common/src/main/java/org/apache/rocketmq/common/namesrv/NamesrvConfig.java)、[`Configuration`](https://github.com/apache/rocketmq/blob/rocketmq-all-5.1.1/remoting/src/main/java/org/apache/rocketmq/remoting/Configuration.java)
- V2 tag：[`rocketmq-all-5.1.2` 同行 `containsKey("configStorePath")`](https://github.com/apache/rocketmq/blob/rocketmq-all-5.1.2/namesrv/src/main/java/org/apache/rocketmq/namesrv/processor/DefaultRequestProcessor.java)
