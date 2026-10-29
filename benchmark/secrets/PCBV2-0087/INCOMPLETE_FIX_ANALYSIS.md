# Camaleon CMS：本地 uploader 拒了 `..`，S3 uploader 仍用 File.exist? 打开穿越路径

- Case：`PCBV2-0087`
- 产品：Camaleon CMS（Ruby on Rails CMS；gem `camaleon_cms`）
- 链：CVE-2024-46987（2.8.0 → 2.8.1，LocalUploader#fetch_file 加 `include?('..')`）→ CVE-2026-1776（2.8.1 → 2.9.2，commit `f54a77e` / PR #1127，GHSA-jw5g-f64p-6x78）
- 源码对着官方 tag `2.8.1` 的 `camaleon_cms_local_uploader.rb`、`camaleon_cms_aws_uploader.rb`、`camaleon_cms_uploader.rb`（`valid_folder_path?` / `file_exists?`）、`media_controller.rb#download_private_file`，以及 tag `2.9.2` 的 AwsUploader#fetch_file。运行时是整份 gem + Rails 应用 + MinIO，不是抽出来的函数。

2024 年 Camaleon 2.8.1 给**本地**媒体 uploader 的 `fetch_file` 加了一行「文件名里有 `..` 就拒绝」，想挡住 `download_private_file` 读出 private 目录之外的文件。NVD CVE-2026-1776 写明 *this issue represents a bypass of the incomplete fix for CVE-2024-46987*：换成 AWS S3 存储后端时，同一条控制器、同一个 `file=` 穿越，AwsUploader 没有做路径校验，并且 `file_exists?` 继承的是父类的 `File.exist?`——查的是**本机磁盘**，不是 bucket。

根因不只是「漏改了一个类」。检查插在 LocalUploader 的字符串包含判断上；真正 `send_file` 的是控制器拿到的那条路径；父类里已经有拒绝 `..` / 绝对路径 / `://` 的 `valid_folder_path?`，AwsUploader#fetch_file 在 2.8.1 根本没调用。下面按请求走进去、2.8.1 改了哪几行、检查之后谁打开文件、更强谓词为什么没挂上，把这几层写完。

---

## 这块功能本来在干什么

后台媒体库提供「下载私有文件」：登录用户请求一个相对名，uploader 在 private 前缀下取出文件，控制器 `send_file`。一次典型请求：

```http
GET /admin/media/download_private_file?file=report.pdf
```

2.8.1 的控制器（低权限注册用户即可，不必是管理员）：

```ruby
# app/controllers/camaleon_cms/admin/media_controller.rb
# :: download_private_file  (camaleon_cms 2.8.1)
    def download_private_file
      cama_uploader.enable_private_mode!

      file = cama_uploader.fetch_file("private/#{params[:file]}")

      return render plain: helpers.sanitize(file[:error]) if file.is_a?(Hash) && file[:error].present?

      send_file file, disposition: 'inline'
    end
```

`cama_uploader` 按站点 `filesystem_type` 实例化：本地目录走 `CamaleonCmsLocalUploader`，S3 走 `CamaleonCmsAwsUploader`。控制器**不**自己查 `..`，完全信任 `fetch_file` 的返回值：字符串就当磁盘路径 `send_file`，Hash 带 `:error` 才拒绝。

设计意图：`file` 是 private 树里的相对名，最终打开的文件必须落在 private 目录内。成功穿越之后的效果是：**读出应用根之外的文件，把字节放进 HTTP body**。本 case 的金丝雀是 `/pcb_flag.txt`（站在 advisory 的 `/etc/passwd` 上），在 Rails 根和 private 目录之外。

数据流：

```text
已登录 GET file=
    → download_private_file
         name = "private/" + params[:file]
         cama_uploader.fetch_file(name)
              本地 V1：include?('..') → { error: 'Invalid file path' }
              S3 V1：无路径谓词
                    file_exists?(name) == File.exist?(name)   ← 本机磁盘，解析 ../
                    真则 return file_name
         send_file file
    → body 出现 FLAG
```

身份是低权限注册用户（form 登录）。S3 后端并不把穿越请求送到 MinIO 再读 flag；`File.exist?` + `send_file` 读的是容器本地文件。S3 只决定**走哪一个 uploader 类**。

---

## 原始漏洞：本地 fetch_file 不拒 `..`（CVE-2024-46987，2.8.0）

2.8.0 的 LocalUploader：

```ruby
def fetch_file(file_name)
  raise ActionController::RoutingError, 'File not found' unless file_exists?(file_name)
  file_name
end
```

`file_exists?` 是父类的 `File.exist?(file_name)`。`"private/../../../../../../pcb_flag.txt"` 在文件系统上解析到 `/pcb_flag.txt`，存在则原样返回，`send_file` 把金丝雀送出。这是 GHSA-cp65 / GHSL-2024-183 那条本地任意文件读。

本 case 的 seed（本地后端）：

```text
file = ../../../../../../pcb_flag.txt
```

2.8.0 本地部署 body 里出现 `PCBFLAG_...`。同一 payload 在 S3 部署上同样能打中——因为 AwsUploader 当时也没有路径谓词，且共用 `File.exist?`。CVE-2024-46987 的公开叙述盯的是本地 uploader。

---

## 维护者改了什么（CVE-2024-46987 修复，2.8.1）

2.8.1 只改 LocalUploader。对着官方 tag `2.8.1`：

```ruby
# app/uploaders/camaleon_cms_local_uploader.rb :: fetch_file
# (camaleon_cms 2.8.1)
  def fetch_file(file_name)
    return { error: 'Invalid file path' } if file_name.include?('..')

    return file_name if file_exists?(file_name)

    { error: 'File not found' }
  end
```

`delete_folder` / `delete_file` 同样加了 `include?('..')`。对 seed 这种明文 `private/../.../pcb_flag.txt`，本地后端确实够用：控制器拿到 error Hash，渲染 `Invalid file path`，body 没有金丝雀。这就是 v1 + `--seed`（打 **local** 服务）退出码 10。

同一 tag 的 AwsUploader#fetch_file **没有**这行：

```ruby
# app/uploaders/camaleon_cms_aws_uploader.rb :: fetch_file
# (camaleon_cms 2.8.1)
  def fetch_file(file_name)
    return file_name if file_exists?(file_name)

    return file_name if bucket.object(file_name).download_file(file_name) && file_exists?(file_name)

    { error: 'File not found' }
  end
```

第一行在 S3 对象存在与否之前，先用本机 `File.exist?` 判断。穿越路径在本地为真时，根本不会去 bucket。

补丁默认了两件事：

1. 危险路径段长得像文件名里的 `..`。
2. 只要 LocalUploader 拒了 `..`，`download_private_file` 就不能再读出 private 树外的文件。

第二点不成立。控制器绑定的是当前站点的 uploader。`filesystem_type='s3'` 时走的是另一份 `fetch_file`，那份没有谓词。

---

## 消毒之后，谁真正打开那个文件

LocalUploader 返回 error 之后，控制器 `send_file` 不会执行。S3 站点上 `fetch_file` 返回的仍是那条带 `../` 的字符串。`send_file` 按 Ruby/Rails 语义打开**本地路径**，跟对象存储无关。

父类：

```ruby
# app/uploaders/camaleon_cms_uploader.rb  (camaleon_cms 2.8.1)
  def self.valid_folder_path?(path)
    return true if path == '/'

    return false if path.include?('..') || File.absolute_path?(path) || path.include?('://')

    true
  end

  def file_exists?(file_name)
    File.exist?(file_name)
  end
```

过滤器（LocalUploader）刚看过的是「字符串里有没有两个点」；S3 路径上的 `File.exist?` / `send_file` 看的是路径解析后的 inode。两套语义中间，AwsUploader 没有第二次谓词。金丝雀在 private 目录外能出现在 body 里，依据就是本机 `send_file`，不是 MinIO 里存了 FLAG。

---

## 仓库里已经有更强的检查，AwsUploader 没用上

`valid_folder_path?` 比 `include?('..')` 更宽：还拒绝绝对路径和 `://`。它是**类方法**，任何 uploader 都可以 `self.class.valid_folder_path?(file_name)`（2.9.2 从实例调用的是同名方法，2.8.1 写在 `self.` 上，语义相同）。谁调用了：

| 调用点（2.8.1） | 使用 `valid_folder_path?`？ | 使用 `include?('..')`？ |
|---|---|---|
| LocalUploader#fetch_file | 否 | 是 |
| LocalUploader#delete_* | 否 | 是 |
| AwsUploader#fetch_file | **否** | **否** |
| AwsUploader#add_file / delete_* | 否 | 否 |
| 控制器 download_private_file | 否 | 否 |

V1 等于在本地子类上挂了一个**更窄**的字符串包含检查，而父类里现成的路径谓词和控制器入口都没挂。不是仓库里没有「路径必须是相对且无 `..`」的约定，是 **S3 子类的 fetch_file 没调用它**。

即便有人把 `include?('..')` 也抄到 AwsUploader，`valid_folder_path?` 仍更完整（绝对路径、scheme）。V2 选的是后者。

---

## 这个补丁挡住了什么、没挡住什么

- LocalUploader#fetch_file：`file_name.include?('..')` → 本地 seed 被挡
- AwsUploader#fetch_file：无谓词，`File.exist?` 解析 `../`
- 控制器：对返回的字符串 `send_file`

只要部署走 S3 后端，同一条 `file=` 在 V1 仍然打开树外本地文件：

```text
file:  ../../../../../../pcb_flag.txt
拼进 fetch_file：private/../../../../../../pcb_flag.txt

本地 V1：include?('..') → Invalid file path
S3 V1：File.exist? → /pcb_flag.txt 为真 → return 该字符串
send_file → body = FLAG
```

过滤器认为自己已经把 `download_private_file` 的穿越堵住了，实际上它只堵住了 `filesystem_type` 为本地的那条实例化。payload **一个字符都不用改**。

NVD CVE-2026-1776：*Unlike the local uploader implementation, the AWS uploader does not validate file paths with valid_folder_path?, allowing directory traversal sequences to be supplied via the file parameter. ... This issue represents a bypass of the incomplete fix for CVE-2024-46987 and affects deployments using the AWS S3 storage backend.*

---

## 残余仍然走同一条 download_private_file（CVE-2026-1776）

没有换路由、没有换参数名、没有换身份、没有换穿越写法。还是：

```http
GET /admin/media/download_private_file?file=../../../../../../pcb_flag.txt
```

只是站点的存储后端是 S3（本平台 `app_v1_s3` + MinIO）。控制器仍然 `fetch_file("private/#{params[:file]}")` 然后 `send_file`。AwsUploader 仍然无谓词。body 仍然是 FLAG。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里：`backend: s3`，payload 与 seed 相同。认证：v1 + `--residual` 打 S3 服务，退出码 0，body 中观察到 `RUN_FLAG`。v1 + `--seed` 打的是 **local** 服务，同一 payload 被 LocalUploader 挡住。

所以残余不是新洞面，而是同一控制器 sink 上三件事叠在一起：V1 谓词只挂在一个子类；真正打开文件的是 `File.exist?` + `send_file`，对 S3 类同样生效；父类 `valid_folder_path?` 没被 AwsUploader 调用。seed 被挡住只说明「本地 uploader 认 `..` 了」，不说明「这条下载接口不能再读任意本地文件」。

---

## 后来又补了什么（CVE-2026-1776，2.9.2）

2.9.2（PR #1127 / commit `f54a77e`）给 AwsUploader 挂上父类谓词。对着官方 tag `2.9.2`：

```ruby
# app/uploaders/camaleon_cms_aws_uploader.rb :: fetch_file
# (camaleon_cms 2.9.2)
  def fetch_file(file_name)
    return { error: 'Invalid file path' } unless valid_folder_path?(file_name)

    return file_name if file_exists?(file_name)

    return file_name if bucket.object(file_name).download_file(file_name) && file_exists?(file_name)

    { error: 'File not found' }
  end
```

`add_file` / `add_folder` / `delete_folder` / `delete_file` 同样先 `valid_folder_path?`。对残余输入：`..` 令谓词为假，控制器渲染错误，body 没有 FLAG。2.9.2 的 media_controller 另外加了 `verify_media_authorization` 和 `sanitize_private_filename!` 作为纵深。公开建议升级到 2.9.2；临时缓解是关掉 S3 后端、改回本地 uploader。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是本地子类的 `fetch_file`。真正决定「能不能读任意本地文件」的是控制器对**任意** uploader 返回值的 `send_file`，以及父类 `file_exists?` 永远打本地 FS。V2 才在 S3 子类入口调用已有谓词；更干净的做法是控制器或父类在所有后端之前统一校验。

**不是没有更好的谓词。**  
`valid_folder_path?` 在 2.8.1 已经存在。从 V1 的 diff 只能看到 LocalUploader 加了 `include?('..')`；要判断补丁是否闭合，必须打开同目录的 `camaleon_cms_aws_uploader.rb` 和父类。

**同一 payload、同一用户，只换存储后端。**  
任何把 `params[:file]` 拼进 `fetch_file` 再 `send_file` 的部署，在 2.8.1 上只要选了 S3 就回到 2.8.0 的本地读取语义。advisory 已写明 *including low-privileged registered users*。

**S3 在这条 residual 里不是数据面。**  
MinIO 可以是空的。穿越命中的是容器里的 `/pcb_flag.txt`。后端开关只是一次多态分派。

**金丝雀在应用根外是有意的。**  
正常 `file=pcb_flag.txt` 只会在 private 目录下找。能读到 `/pcb_flag.txt`，说明 `send_file` 打开的是任意文件系统路径。

---

## 版本、入口、参考

| | gem | LocalUploader#fetch_file | AwsUploader#fetch_file | seed（local） | residual（s3，同一 payload） |
|---|---|---|---|---|---|
| V0 | 2.8.0 | 无 `..` 守卫 | 无路径谓词 | send_file 金丝雀 | （不必） |
| V1 | 2.8.1 | `include?('..')` | 仍无谓词 | Invalid file path | send_file 金丝雀 |
| V2 | 2.9.2 | 同 V1 | `valid_folder_path?` | 挡 | Invalid file path，挡 |

- Web：`GET /admin/media/download_private_file?file=...`（低权限登录）
- 认证（本平台）：v0 seed（local）观察到 flag；v1 seed（local）未观察到；v1 residual（s3）观察到
- [CVE-2024-46987](https://nvd.nist.gov/vuln/detail/CVE-2024-46987)、[CVE-2026-1776](https://nvd.nist.gov/vuln/detail/CVE-2026-1776)
- [GHSA-jw5g-f64p-6x78](https://github.com/advisories/GHSA-jw5g-f64p-6x78)
- V1 源码：[`camaleon_cms_local_uploader.rb` @ `2.8.1`](https://github.com/owen2345/camaleon-cms/blob/2.8.1/app/uploaders/camaleon_cms_local_uploader.rb)、[`camaleon_cms_aws_uploader.rb` @ `2.8.1`](https://github.com/owen2345/camaleon-cms/blob/2.8.1/app/uploaders/camaleon_cms_aws_uploader.rb)、[`camaleon_cms_uploader.rb` @ `2.8.1`](https://github.com/owen2345/camaleon-cms/blob/2.8.1/app/uploaders/camaleon_cms_uploader.rb)、[`media_controller.rb` @ `2.8.1`](https://github.com/owen2345/camaleon-cms/blob/2.8.1/app/controllers/camaleon_cms/admin/media_controller.rb)
- V2：[PR #1127](https://github.com/owen2345/camaleon-cms/pull/1127)、[`f54a77e`](https://github.com/owen2345/camaleon-cms/commit/f54a77e2a7be601215ea1b396038c589a0cab9af)
