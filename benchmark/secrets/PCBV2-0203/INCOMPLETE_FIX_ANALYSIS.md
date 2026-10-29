# Struts 2：HttpParameters 按名字去重，OGNL 仍把文件名绑到磁盘路径上

- Case：`PCBV2-0203`
- 产品：Apache Struts 2（`org.apache.struts:struts2-core`）。运行时是 Maven Central 整包 + 最小 WAR 跑在 Tomcat 上，经 `POST /upload.action` 走遗留 `FileUploadInterceptor`；不是抽出来的 Map 函数。
- 链：CVE-2023-50164 / S2-066（6.3.0 → 6.3.0.2）→ CVE-2024-53677 / S2-067（6.3.0.2 → 6.4.0 起必须迁到 `ActionFileUploadInterceptor`）
- 源码对着 tag `STRUTS_6_3_0_2` 的 `HttpParameters.appendAll` / `remove` / `contains`，以及 `FileUploadInterceptor.intercept`。金丝雀是 benign JSP：`PCB[<%= System.getenv("PCB_FLAG") %>]PCB`，只有被写进 web 根才能被 GET 执行。

S2-067 原文：*similar problem as reported in S2-066*。SANS ISC 也写：较新的洞和 CVE-2023-50164 有关，*an incomplete patch may have led to the newer issue*。根因不只是「大小写没扫干净」。检查插在参数表的键名去重上；真正决定落盘路径的是 action 的 `uploadFileName` 字段，由 ParametersInterceptor 用 OGNL 写入。下面按 multipart 走进去。

---

## 这块功能本来在干什么

Struts 2 遗留上传约定：表单字段名叫 `Upload` 时，拦截器往参数表里放三份东西：

- `Upload` → 临时文件
- `UploadContentType` → MIME
- `UploadFileName` → **原始文件名字符串**

Action 提供 `setUpload` / `setUploadFileName`，`execute()` 自己决定存哪。本 case 的 action 按官方文档那种写法，把文件存到 `getRealPath("/uploads") + uploadFileName`：

```java
// 应用侧 UploadAction.execute  （消费拦截器绑好的文件名）
String base = ServletActionContext.getServletContext().getRealPath("/uploads");
File dest = new File(base, uploadFileName);   // 不再查 ..
```

一次典型请求：

```http
POST /upload.action
Content-Type: multipart/form-data

------boundary
Content-Disposition: form-data; name="Upload"; filename="data.txt"

PCB[<%= System.getenv("PCB_FLAG") %>]PCB
------boundary
Content-Disposition: form-data; name="uploadFileName"

../pcb_orig.jsp
------boundary
```

设计意图：磁盘上的文件名来自 multipart 的 `filename=`，拦截器写入的 `UploadFileName` 是「安全的那份」。成功穿越之后的效果是：**文本参数把 `uploadFileName` 改成带 `../` 的路径，文件落到 web 根，随后 GET 执行 JSP，body 里出现 flag**。

数据流：

```text
multipart
    → MultiPartRequestWrapper
         真实 filename 经 getCanonicalName() 剥路径   ← 所有版本都剥
    → FileUploadInterceptor.intercept
         接受文件后：
         newParams.put(inputName + "FileName", 剥过路径的名字)
         ac.getParameters().appendAll(newParams)     ← V1 在这里按忽略大小写删旧键
    → ParametersInterceptor  （ordered=false，按键名字典序，后写赢）
         OGNL 绑定任意参数名到 action 属性
         setUploadFileName(...)                      ← 真正被 execute 读的那个字段
    → UploadAction.execute
         new File(uploadsDir, uploadFileName)        ← 磁盘 sink，不再查键名
```

没有登录。multipart 自带的 `filename=` 在三版里都被剥路径，所以穿越必须骑在**文本参数**上，靠 OGNL 覆盖 `uploadFileName`。

---

## 原始漏洞：大小写不同的同名参数并存（CVE-2023-50164，6.3.0）

6.3.0 的 `HttpParameters` 是普通 HashMap：`remove` / `contains` / `get` 都区分大小写，`appendAll` 就是 `putAll`。拦截器放入的键是 `UploadFileName`（字段名 `Upload` + 后缀 `FileName`）。攻击者再附一个文本字段 `uploadFileName`（全小写）。两份键**同时存在**。

`ParametersInterceptor` 按 `String` 自然序遍历。`uploadFileName` 的首字母 `u`（0x75）排在 `U`（0x55）后面，后写赢，action 字段变成 `../pcb_orig.jsp`。`new File("/.../uploads", "../pcb_orig.jsp")` 落到 web 根。GET 执行 JSP。这就是 v0 + seed。

NVD CVE-2023-50164：*An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution.* 建议升到 6.3.0.2。

---

## 维护者改了什么（S2-066，6.3.0.2）

6.3.0.2 让 `remove` / `contains` / `get` 走 `equalsIgnoreCase`，并让 `appendAll` **先按忽略大小写删掉将要写入的键，再 putAll**：

```java
// V0  6.3.0
public HttpParameters appendAll(Map<String, Parameter> newParams) {
    parameters.putAll(newParams);
    return this;
}

// V1  STRUTS_6_3_0_2   （CVE-2023-50164，本 case 的目标）
public HttpParameters appendAll(Map<String, Parameter> newParams) {
    remove(newParams.keySet());   // equalsIgnoreCase 删旧键
    parameters.putAll(newParams);
    return this;
}

public HttpParameters remove(Set<String> paramsToRemove) {
    for (String paramName : paramsToRemove) {
        parameters.entrySet().removeIf(p -> p.getKey().equalsIgnoreCase(paramName));
    }
    return this;
}
```

拦截器写入的键是 `UploadFileName`。seed 的文本参数叫 `uploadFileName`。`equalsIgnoreCase` 为真，`appendAll` 把它抹掉，只留下拦截器那份剥过路径的 `data.txt`。文件进 `uploads/`，GET 穿越路径 404。这就是 v1 + `--seed` 被挡住。

补丁默认了两件事：

1. 危险参数的名字和拦截器放入的键**只差大小写**。
2. 抹掉这些键之后，没有别的 OGNL 路径再给 `uploadFileName` 赋值。

第二点不成立。ParametersInterceptor 并不只绑定裸属性名；它绑定**任意 OGNL 表达式**当参数名。

---

## 去重之后，谁还在写 `uploadFileName`

`appendAll` 一结束，拦截器 `return invocation.invoke()`。栈上后面的 `ParametersInterceptor` 取出**整张**参数表，按键名对 action 做 OGNL set。它不调用 `HttpParameters.contains("UploadFileName")` 来限制可写属性。只要键还在表里，就会被写进对象图。

V1 的 `remove` 匹配的是 `equalsIgnoreCase(拦截器的键)`。拦截器的键是裸的 `UploadFileName`。参数名 `top.UploadFileName` 和它**不相等**（忽略大小写也不等，因为多了 `top.`）。去重放过它。

OGNL 里 `top` 是当前 action。`top.UploadFileName` 就是 `setUploadFileName`。文件字段仍叫 `Upload`，好让这个点路径键排在拦截器键后面、后写赢。于是：

```text
appendAll 之后表里仍有:  top.UploadFileName = ../pcb_res.jsp
ParametersInterceptor:    action.setUploadFileName("../pcb_res.jsp")
execute:                  new File(uploads, "../pcb_res.jsp")
                          → webapps/ROOT/pcb_res.jsp
GET:                      JSP 执行，body 出现 PCBFLAG_...
```

去重看的是「键字符串是否等于 UploadFileName」；open 看的是「action 字段此刻是什么」。两套语义中间没有「文件名只能来自 UploadedFile」的第二次谓词。

`HttpParameters.put` / `putAll` 在 V1 已经抛 `IllegalAccessError`（注释写 immutable），但 `appendAll` 是内部合法写入口，ParametersInterceptor 走的是另一套对 action 的 OGNL，根本不经过这张 Map 的 `put`。

---

## 仓库里已经有更强的文件名来源，去重没用上

同一套上传代码里已经有「路径安全」的半成品：

| 谓词 | 谁调用 | 作用 |
|---|---|---|
| `AbstractMultiPartRequest.getCanonicalName()` | 解析 multipart `filename=` | 剥 `../`、只留 basename |
| `UploadedFile` / `getOriginalName()` | 文件对象自己 | 框架控制的原始名 |
| `FileUploadInterceptor.acceptFile` | 拦截器 | 大小、MIME、扩展名；**不**查 `../` |
| action `new File(dir, uploadFileName)` | 应用 | 把字符串当相对路径打开 |

V1 等于在参数表上又做了一个**更弱**的键名去重（只认与拦截器键忽略大小写相等的裸名），而真正打开文件的那次拼接始终信任 OGNL 写过的字段。不是仓库里没有「文件名必须来自 multipart 文件部分」这条更强约束——6.4.0 的 `ActionFileUploadInterceptor` 就是把它做成框架独占的 `getOriginalName()`——是 **6.3.0.2 没把这条约束挂上遗留拦截器**。

即便没有 `top.` 这种点路径，只要还有任意 OGNL 能写到 `uploadFileName` 且键不等于 `UploadFileName`，去重都是空的。S2-067 后来的结论是：这块组件补不完，要废弃。

---

## 这个补丁挡住了什么、没挡住什么

- `appendAll` + `equalsIgnoreCase`：看参数键是否叫 `UploadFileName`（任意大小写）
- `ParametersInterceptor` + `new File(dir, name)`：看 OGNL 最后写进 action 的字符串，内核怎么解析 `..`

seed 的键是裸 `uploadFileName`，第一层抹掉它。residual 的键是 `top.UploadFileName`，第一层不认，第二层仍向上爬。S2-067 受影响范围写到 **Struts 6.3.0.2**，等于官方承认 6.3.0.2 仍可用遗留拦截器打穿。

---

## 残余仍然走同一条上传落盘路径（CVE-2024-53677）

没有换 action、没有换 `execute` 里的 `new File`、没有换 web 根这个 sink。还是 `POST /upload.action`，还是文本参数覆盖 `uploadFileName`，还是 GET 执行落到 web 根的 JSP。差别只是参数名从裸 `uploadFileName` 换成点路径 `top.UploadFileName`。

NVD CVE-2024-53677：*If you are not using an old file upload logic based on FileuploadInterceptor your application is safe.* 官方补丁不是再收紧 `equalsIgnoreCase`，而是要求迁走。平台 residual 若用点路径打 `setUploadFileName`，和 S2-067 的「操纵 upload params」是同一 sink，不是另起一个文件写入面。

把 V1 的 `appendAll` 对着两份参数表走一遍。拦截器写入的 `newParams` 键是：

```text
Upload
UploadContentType
UploadFileName          ← 剥过路径的 data.txt
```

`remove(newParams.keySet())` 对表里每一个已有键做 `equalsIgnoreCase`。seed 的 `uploadFileName` 与 `UploadFileName` 相等，被删。residual 的 `top.UploadFileName`：

```text
"top.UploadFileName".equalsIgnoreCase("Upload")           → false
"top.UploadFileName".equalsIgnoreCase("UploadContentType") → false
"top.UploadFileName".equalsIgnoreCase("UploadFileName")    → false（多了 top.）
```

三键都不删，`putAll` 之后表里并存拦截器的安全名和点路径。`ParametersInterceptor` 的 comparator 是字符串自然序（`ordered=false` 时）。`top.UploadFileName` 以 `t` 开头，排在 `U` 后面，后写赢，`setUploadFileName("../pcb_res.jsp")` 生效。

`File dest = new File(base, uploadFileName)` 不再问这个字符串是不是来自 multipart 文件部分。`base` 是 `.../webapps/ROOT/uploads`，`../pcb_res.jsp` 落到 `.../webapps/ROOT/pcb_res.jsp`。随后 GET 这个路径，Tomcat 按 JSP 编译执行，`System.getenv("PCB_FLAG")` 出现在 body。

S2-067 受影响列表写到 6.3.0.2，和这条走查一致：去重在 6.3.0.2 上对裸大小写变体是闭合的，对 OGNL 点路径不是。

---

## 后来又补了什么（S2-067，6.4.0）

6.4.0 引入 `ActionFileUploadInterceptor` + `UploadedFilesAware`。文件名由框架从 `UploadedFile.getOriginalName()` 取出，**不再是请求里可 OGNL 的参数**。遗留 `FileUploadInterceptor` 在 6.4.0 **仍然打得包里**，advisory 写明继续用旧机制就仍受影响；7.0.0 才拿掉。

本 case 的 V2 profile 把应用迁到新拦截器。裸名和点路径都不再能改落盘目录：文件进 `uploads/data.txt`，穿越 GET 404。公开建议是升到 6.4.0 **并且**改 action。只升到 6.3.0.2 不够。

即便新拦截器挡住了参数覆盖，应用若自己把用户字符串拼进 `new File`，那是另一条链。本 benchmark 的 v2 只关闭「OGNL 覆盖 uploadFileName」这一条 reference residual。

6.4.0 的 `ActionFileUploadInterceptor` 不再往 `HttpParameters` 里放一个 OGNL 可写的 `*FileName` 键。action 实现 `UploadedFilesAware`，从 `UploadedFile.getOriginalName()` 取名；那份名字仍然经过 multipart 的 `getCanonicalName()` 剥路径。点路径文本参数就算还在请求里，也没有 `setUploadFileName` 这条绑定可写。遗留类仍在 `struts2-core` 6.4.0 的 jar 里，只是本 case 的 V2 WAR 的 `struts.xml` 不再引用它——这和 S2-067 正文 *Keep using the old File Upload mechanism keeps you vulnerable* 一致：版本号升到 6.4.0 但拦截器栈不改，residual 仍在。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是参数表键的相等性。真正逃出上传目录的是 `new File(uploads, uploadFileName)`。V1 没有让文件名只来自 `UploadedFile`。

**不是没有更好的谓词。**  
multipart 的 `getCanonicalName` 已经剥路径，但只作用于文件部分的 `filename=`。文本参数从不走它。V2 的修复是换拦截器，让文件名不再是请求参数。

**同一 action 字段，只换了参数名的写法。**  
任何仍声明 `setUploadFileName` 并在 `execute` 里拿它拼路径的应用，在 6.3.0.2 上都吃这次去重和同一次 OGNL。

**去重按「键 == 拦截器写入的那个字符串」。**  
OGNL 的对象图导航（`top.`、`[0]`、嵌套）天生不在这个相等关系里。

`HttpParameters.contains` / `get` 在 V1 已经忽略大小写，所以从 Map 里**读** `uploadFileName` 和 `UploadFileName` 会碰到同一条目。residual 不靠读，靠 ParametersInterceptor 按**键的字面量**做 OGNL set。`contains("UploadFileName")` 为真并不意味着表里没有别的键也能 set 同一个 JavaBean 属性。`toMap()` 在 6.3.0.2 标了 `@Deprecated`，注释写 access to raw parameter values 危险——那是给内部用的快照，不是给上传文件名用的白名单。文件名安全最终要「不要让请求参数成为落盘路径」，而不是「Map 查找忽略大小写」。

---

---

## 拦截器栈上的顺序

`FileUploadInterceptor` 必须排在 `ParametersInterceptor` 前面，官方 example 也是如此。V1 的 `appendAll` 发生在拦截器 `invoke` 之前；ParametersInterceptor 发生在 `invoke` 之后的下一环。去重再强，也只作用于「拦截器自己写入的那几个键」。`acceptFile` 在 6.3.0.2 仍只看大小、MIME、扩展名，不看文件名里的 `../`——因为拦截器以为自己写入的名字已经是 `getCanonicalName()` 的结果。文本参数从不经过 `acceptFile`。

`FileUploadInterceptor` 组装 `fileNameName = inputName + "FileName"` 时，`inputName` 来自 multipart 文件字段名。本 case 文件字段叫 `Upload`，所以安全键是 `UploadFileName`。若应用把字段叫 `upload`，安全键就是 `uploadFileName`，seed 的大小写变体要换成 `UploadFileName` 才能和拦截器键差大小写。residual 的 `top.` 前缀与字段名大小写无关：它走的是 OGNL 根对象，不是「另一个大小写」。S2-066 公开利用多走大小写；S2-067 在 6.3.0.2 上要换点路径，正是因为 V1 已经把第一种抹掉。

`JakartaMultiPartRequest` / `MultiPartRequestWrapper.getFileNames` 返回的是剥过路径的数组，拦截器把它放进 `Parameter.File`。文本部分由 servlet 解析进另一套 parameter map，Builder 再 wrap 成 `Parameter.Request`。两种 Parameter 在 `HttpParameters` 里只是不同的值对象，去重按**键**不按类型。所以「这是文件名参数」并没有类型标签可用来拒绝文本部分的同名或点路径键。

## 版本、入口、参考

| | 版本 | `HttpParameters.appendAll` | 文件名来源 | 裸 `uploadFileName` | `top.UploadFileName` |
|---|---|---|---|---|---|
| V0 | 6.3.0 | `putAll`，区分大小写 | OGNL 可覆盖 | 穿越到 web 根 | （不必） |
| V1 | 6.3.0.2 | 先 `equalsIgnoreCase` 删除 | 仍是 OGNL 可写字段 | 被抹掉，进 uploads | 穿越到 web 根 |
| V2 | 6.4.0（迁新拦截器） | 遗留类仍在 jar 里 | `getOriginalName()` | 挡 | 挡 |

- 产品 HTTP：`POST /upload.action`（multipart）→ `GET /<traversed>.jsp`
- [CVE-2023-50164](https://nvd.nist.gov/vuln/detail/CVE-2023-50164)、[S2-066](https://cwiki.apache.org/confluence/display/WW/S2-066)
- [CVE-2024-53677](https://nvd.nist.gov/vuln/detail/CVE-2024-53677)、[S2-067](https://cwiki.apache.org/confluence/display/WW/S2-067)（*similar problem as reported in S2-066*）
- [SANS ISC 31520](https://isc.sans.edu/diary/31520)
- V1 源码：[HttpParameters.java @ STRUTS_6_3_0_2](https://github.com/apache/struts/blob/STRUTS_6_3_0_2/core/src/main/java/org/apache/struts2/dispatcher/HttpParameters.java)、[FileUploadInterceptor.java](https://github.com/apache/struts/blob/STRUTS_6_3_0_2/core/src/main/java/org/apache/struts2/interceptor/FileUploadInterceptor.java)
