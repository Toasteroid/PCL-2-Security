# ModSecret.txt 安全评估报告

> 评估对象：`ModSecret.txt`（PCL2 启动器联网配置/公告/更新模块，VB.NET，186 行）
> 评估方式：人工整理
> 评估日期：2026-10-24

---

## 一、概述

`ModSecret.txt` 是 PCL2（Plain Craft Launcher 2，一个 Minecraft 启动器）的 `联网配置` 区块。其核心为一个由后台 `LoaderTask` 周期性调用的 `ServerSub` 子程序，负责：

1. 清理旧的更新缓存 `update.exe`；
2. 读取本地缓存的配置与公告；
3. 向硬编码的腾讯云 COS 桶 `pcl2-server-1253424809.file.myqcloud.com` 拉取 `notice.cfg`、`ServerConfig.json`、`notice.json`；
4. 解析服务器下发的"公告"，并**无条件执行其中声明的动作（actions）**：`copy` / `website` / `stop` / `setup` / `update` / `slientupdate`。

**根本问题（信任模型）**：整段代码**完全信任远端服务器**。所有行为（配置版本判断、动作执行、更新源地址）均由服务器下发内容驱动，对下载的配置、公告、更新文件**没有任何来源鉴权、签名校验或完整性校验**。这是后续所有高危风险的根因。

在正常运营下，风险由"开发者可信"吸收；但一旦远端 COS 桶失陷、DNS 劫持或传输链路被中间人（MITM）篡改（尤其当底层 HTTP 客户端禁用证书校验时），攻击者即可通过该模块在全部客户端上实现**远程代码执行（RCE）与远程控制**。

---

## 二、综合评级

| 项目 | 评级 |
|---|---|
| **综合风险评级** | **高危（High）** |
| 后门 / 远程控制 | 高危 |
| 下载与更新安全（无校验、服务器定更新源） | 高危 |
| 信息泄露（设备指纹 / 版本外发） | 中危 |
| 解析与注入（健壮性 / 类型混淆） | 中危 |
| 其他（硬编码桶、{CDN} 链、临时路径、FIPS） | 中危 |

**综合评级结论：高危（High）。** 本模块实现了一个完全信任远端服务器的远程动作执行框架，且对下载内容零校验。一旦"服务器 / 托管桶 / 传输链路"任一环节失陷，即具备远程代码执行与远程控制能力，影响面为 PCL2 的全部用户群。

---

## 三、漏洞清单

> 命名规则：每个漏洞以 `PCL-` 开头，编号后以其**漏洞类型**作为名称（如 `PCL-RCE-001 远程代码执行`）。
> 严重程度：🔴 高危 / 🟠 中危 / 🟡 低危 / ⚪ 信息。
> 以下"精选源代码"为原始文件对应行（已保留原始缩进与行号前缀）。

### PCL-RCE-001 远程代码执行（无约束的服务器动作执行通道）
- **类型**：远程代码执行 / 远程控制（设计信任模型缺陷）
- **源代码**：
  ```vb
  149  For Each Action As JProperty In Actions
  150      Try
  151          Select Case Action.Name
  152              Case "copy"
  153                  ClipboardSet(Action.Value.ToString)
  154              Case "website"
  155                  OpenWebsite(Action.Value.ToString)
  156              Case "stop"
  157                  FrmMain.EndProgram(False)
  158              Case "setup" '仅支持 >= 388
  159                  Dim Values As JObject = Action.Value
  160                  For Each Value In Values
  161                      Settings.Set(Value.Key, Value.Value.ToString)
  162                  Next
  163              Case "update", "slientupdate" '>= 392 起，不再使用 UpdateInfo 中的 url 参数，而是直接从 ServerConfig.json 读取
  164                  Dim UpdateInfo As JObject = Action.Value
  165                  Dim Silent As Boolean = Action.Name = "slientupdate"
  166                  If Not HasUpdatePermission Then
  167                      If Not Silent Then InputPotatoCode(True)
  168                      If Not HasUpdatePermission Then Continue For
  169                  End If
  170                  UpdateStart(Silent)
  171              Case Else
  172                  Throw New Exception("未知的行动支：" & Action.Name & ", " & Action.Value.ToString)
  173          End Select
  174      Catch ex As Exception
  175          Logger.Error(ex, $"执行 PCL 服务器公告动作失败（{Action.Name}, {Action.Value}）", LogBehavior.Toast)
  176      End Try
  177  Next
  ```
- **说明**：这是整份代码**最核心的风险点**，也是其它 RCE 类漏洞共用的"执行通道"。客户端在解析服务器下发的公告后，会遍历其中的 `actions` 集合，并以 `Action.Name`（动作名）作为 `Select Case` 分支键、以 `Action.Value` 作为参数，逐条分发执行。关键点在于：
  1. **完全无来源鉴权**：代码不校验该公告来自哪个服务器、是否经过签名、是否在可信通道内，只要 HTTP 请求拿到了 JSON 就照单全收。
  2. **动作集开放可扩展**：`Case Else`（第 171–172 行）仅抛异常并被第 174 行 `Catch` 吞掉（仅记录日志 + Toast）。这意味着动作集合是**开放**的——服务器随时可引入新的高危动作类型（如执行命令、写文件），客户端没有任何拦截或白名单能力。
  3. **参数直接透传**：`website`/`copy` 直接把 `Action.Value.ToString` 交给 `OpenWebsite`/`ClipboardSet`；`setup` 把任意键值对写入本地设置；`update`/`slientupdate` 触发更新。所有参数均由服务器内容决定，客户端不做安全过滤。
  4. **错误被静默吞掉**：执行失败仅记日志，不会中断整个公告循环，攻击者可在同一公告中混入多条动作，部分成功即可达成目的。
  因此，在"服务器被控 / 响应被 MITM"的前提下，这个分支结构等价于一个**无鉴权、可远程触发的命令执行解释器**。
- **可能的利用方法**：
  - 攻击者控制 COS 桶或劫持响应后，下发包含 `update`/`slientupdate` 或 `setup`+`{CDN}` 链的公告；
  - 客户端自动解析并执行对应动作，无需用户干预。
- **可能的后果**：在全部客户端上实现远程代码执行、远程控制、批量植入恶意程序，造成大规模供应链攻击。
- **严重程度**：🔴 高危

### PCL-RCE-002 权限提升 / 任意设置篡改（setup 动作无白名单）
- **类型**：权限提升 / 配置篡改
- **源代码**：
  ```vb
  158  Case "setup" '仅支持 >= 388
  159      Dim Values As JObject = Action.Value
  160      For Each Value In Values
  161          Settings.Set(Value.Key, Value.Value.ToString)
  162      Next
  ```
- **说明**：`setup` 动作将服务器下发的 JSON 对象 `Action.Value` 逐字段遍历，对每个 `Value.Key`（设置名）调用 `Settings.Set(Value.Key, Value.Value.ToString)` 写入本地设置存储。**没有任何键名白名单、类型校验或安全敏感键拦截**。注意以下几点：
  1. **注释"仅支持 >= 388"是版本门槛而非安全控制**：它只限制哪些客户端版本能处理该动作，但服务器已知客户端版本（见 PCL-INFO-001），可只对兼容客户端下发，无法阻止攻击。
  2. **可改写安全相关设置**：若该设置系统管理更新源、`{CDN}` 解析域名、代理、或"最高保存版本""公告过滤阈值"（如 `SystemSystemActivity`/`SystemSystemUpdate`，见第 122 行）等，攻击者即可借此改变程序后续的下载目标与行为过滤。
  3. **类型污染**：不论原值是数字、布尔还是对象/数组，`Value.Value.ToString` 统一转字符串写入；若 `Action.Value` 内某值是 `JObject`/`JArray`，`.ToString` 会得到 JSON 文本并被写入设置存储，造成后续逻辑的类型混乱。
  4. **与更新链组合**：一旦能改写 CDN/更新源设置，即可与 PCL-RCE-003、PCL-CHAIN-001 链式构成稳定的 RCE 通道。
- **可能的利用方法**：
  - 下发 `setup` 动作改写更新源、`{CDN}`、代理、版本阈值等设置；
  - 配合 `update` 或 `{CDN}` 重定向，将后续所有下载导向攻击者基础设施。
- **可能的后果**：绕过用户"不显示某重要级公告"的意愿；与更新机制链式组合形成 RCE；持久化篡改客户端行为。
- **严重程度**：🔴 高危

### PCL-RCE-003 不安全的更新机制（update/slientupdate 远程触发下载执行）
- **类型**：远程代码执行（不安全更新）
- **源代码**：
  ```vb
  14   If FileUtils.Exists(Paths.Base & "PCL\update.exe") Then
  15       FileUtils.Delete(Paths.Base & "PCL\update.exe")
  ...
  81   NetDownloadByClient("https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json{CDN}", LocalConfigPath)
  ...
  163  Case "update", "slientupdate" '>= 392 起，不再使用 UpdateInfo 中的 url 参数，而是直接从 ServerConfig.json 读取
  164      Dim UpdateInfo As JObject = Action.Value
  165      Dim Silent As Boolean = Action.Name = "slientupdate"
  166      If Not HasUpdatePermission Then
  167          If Not Silent Then InputPotatoCode(True)
  168          If Not HasUpdatePermission Then Continue For
  169      End If
  170      UpdateStart(Silent)
  ```
- **说明**：本漏洞揭示了更新流程的信任链条。第 14–15 行在每次启动时删除 `Paths.Base & "PCL\update.exe"`，说明该路径是更新器**预期的执行入口**（旧更新包先清理、新更新包随后落盘并执行）。而第 163 行的注释明确写道：自 >= 392 起，**更新不再使用公告里的 URL 参数，而是"直接从 ServerConfig.json 读取"更新信息**。而 `ServerConfig.json` 本身是从服务器下载（第 81 行）且**无签名校验**（见 PCL-DL-001）。由此形成完整链路：
  1. 攻击者篡改 `ServerConfig.json` 中的更新源地址为恶意 `update.exe`；
  2. 通过公告的 `update`/`slientupdate` 动作触发 `UpdateStart(Silent)`；
  3. 客户端下载并执行被替换的 `update.exe`，实现 RCE。
  此外，`slientupdate`（静默更新）与 `update` 共用同一权限校验（第 166–169 行 `HasUpdatePermission`/`InputPotatoCode`），若该权限因任何原因被置位或绕过，则更新将在**用户无感知**下完成。注：`update.exe` 是否最终被执行取决于 `UpdateStart` 的实现，需在外部实现中确认，但"下载 + 落盘到执行入口路径"的语义已具备高危前提。
- **可能的利用方法**：
  - 篡改 `ServerConfig.json` 中的更新源地址为攻击者控制的 `update.exe`；
  - 通过公告 `update`/`slientupdate` 动作触发下载并执行该恶意更新程序。
- **可能的后果**：直接 RCE；恶意更新程序获得与启动器相同的权限运行。
- **严重程度**：🔴 高危

### PCL-SILENT-001 静默执行危险动作（无 buttons 公告）
- **类型**：远程控制 / 未授权执行
- **源代码**：
  ```vb
  128  Dim Actions As Object = {}
  129  If ButtonCount > 0 Then
  130      Logger.Info($"显示公告 {NoticeId}：{Description}")
  131      Dim MsgBoxResult As Integer
  132      Select Case ButtonCount
  133          Case 1
  134              MsgBoxResult = MyMsgBox(Description, Title, If(Buttons(0)("text"), "确定").ToString, ForceWait:=True)
  ...
  143      MsgBoxResult = MsgBoxResult.Clamp(1, ButtonCount)
  144      Actions = If(Buttons(MsgBoxResult - 1)("actions"), {})
  145  Else
  146      Actions = If(Notice("actions"), {})
  147  End If
  148  '执行事件
  149  For Each Action As JProperty In Actions
  ```
- **说明**：公告的处理分为两条路径。当 `ButtonCount > 0`（有按钮）时，动作来自用户点击的按钮对应的 `actions`（第 144 行），至少经过了一次用户交互；但当 `ButtonCount = 0`（无 `buttons` 字段）时，代码走入第 145–147 行的 `Else` 分支，**直接使用公告顶层的 `actions` 字段**，并在第 149 行起的循环中**无任何弹窗、无任何用户点击**地自动执行。这意味着：
  1. 服务器只需下发一段**不含 `buttons`** 的公告，就能让客户端静默执行任意动作组合；
  2. 可静默触发的危险动作包括：`website`（打开任意网址，可能被导向钓鱼页，若 `OpenWebsite` 未限制协议甚至可能触发 `file://`/UNC）、`copy`（向剪贴板写入任意内容用于社工诱导）、`stop`（强制退出，见 PCL-DOS-001）、`setup`（静默改设置）等；
  3. 用户对此**完全无感知、无确认、无撤销机会**，显著放大了 PCL-RCE-001 的实际危害面。
- **可能的利用方法**：
  - 下发无按钮公告，静默执行 `website`（打开任意网址）、`copy`（篡改剪贴板）、`stop`（强制退出）、`setup`（改设置）等。
- **可能的后果**：用户无感知地被导向钓鱼页、剪贴板被植入恶意命令、程序被强制终止（DoS）、设置被静默篡改。
- **严重程度**：🔴 高危

### PCL-DOS-001 远程拒绝服务（stop 动作）
- **类型**：拒绝服务（DoS）
- **源代码**：
  ```vb
  156  Case "stop"
  157      FrmMain.EndProgram(False)
  ```
- **说明**：`stop` 动作直接调用 `FrmMain.EndProgram(False)` 终止整个启动器进程，`False` 参数通常表示"非用户主动退出 / 不保存状态"。该动作同样由服务器下发的公告驱动，无任何条件限制或二次确认。攻击者可在任意公告（尤其配合 PCL-SILENT-001 的无按钮公告）中混入 `stop`，使客户端在启动/更新检查阶段被随时强制关闭。虽然单次 DoS 危害低于 RCE，但它可被用作：① 骚扰或阻断用户正常使用；② 在其它攻击（如投毒更新）执行中途强制结束以破坏回滚/提示；③ 与 `website`/`copy` 组合形成"先弹窗诱导、再强制退出"的社工链。
- **可能的利用方法**：在批量公告中混入 `stop` 动作，或在特定条件（如特定设备/版本）下触发。
- **可能的后果**：启动器被随时强制关闭，影响可用性；可作为骚扰或配合其他攻击的干扰手段。
- **严重程度**：🟠 中危

### PCL-INFO-001 信息泄露（设备指纹外发）
- **类型**：敏感信息泄露
- **源代码**：
  ```vb
  41   ServerContent = NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.cfg{CDN}")
  81   NetDownloadByClient("https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json{CDN}", LocalConfigPath)
  96   NoticeContent = NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.json{CDN}", RequireJson:=True)
  ...
  108  For Each Notice As JObject In NoticeContent.Replace("{UNIQUE}", Identify).DeserializeJson()
  ```
- **说明**：第 108 行 `NoticeContent.Replace("{UNIQUE}", Identify)` 证明客户端持有一个持久化的设备标识 `Identify`（通常是安装 ID 或硬件指纹），并在本地把公告内容中的 `{UNIQUE}` 占位符替换为该真实标识。结合 PCL2 既有的请求约定（配置/公告请求 URL 通常会追加 `?v=版本号&id=Identify` 之类的查询参数），`Identify` 与 `VersionCode`（如第 50 行）**极可能以查询参数形式随每一次 HTTPS 请求明文发往服务器**。其风险体现在：
  1. **长期跨会话追踪**：`Identify` 是稳定指纹，服务器可对每台设备做持久画像、关联历史行为、统计活跃度，甚至结合其它数据定位具体用户；
  2. **传输层暴露**：上述 URL 虽为 `https://`，但若底层 HTTP 客户端禁用了证书校验（见 PCL-MITM-001），该标识将在传输中被中间人截获；
  3. **范围可控性缺失**：代码未对标识做随机化、加盐或按需发送，默认全量外发。
  需说明：HTTPS 提供了链路加密，因此该泄露在"正常传输"下主要表现为**服务器端的可追踪性**，而非明文广播；但在 MITM 场景下升级为实时泄露。
- **可能的利用方法**：
  - 服务器端收集并关联 `Identify`，对每台设备做长期、跨会话追踪；
  - 若底层 TLS 校验被弱化（见 PCL-MITM-001），该标识在传输中被中间人截获。
- **可能的后果**：用户设备被持续追踪、画像；结合其它数据可定位特定用户；隐私泄露。
- **严重程度**：🟠 中危

### PCL-DL-001 下载内容无完整性校验（缺签名/哈希/证书固定）
- **类型**：不安全下载 / 缺少完整性校验
- **源代码**：
  ```vb
  27   LocalConfigVersion = Val(ServerConfig("Version")) '读取本地版本号
  ...
  81   NetDownloadByClient("https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json{CDN}", LocalConfigPath)
  82   ServerConfig = FileUtils.ReadAsJson(LocalConfigPath)
  ...
  96   NoticeContent = NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.json{CDN}", RequireJson:=True)
  ```
- **说明**：所有从服务器获取的内容——`notice.cfg`（第 41 行）、`ServerConfig.json`（第 81–82 行）、`notice.json`（第 96 行），以及最终由 `UpdateStart` 触发的 `update.exe`——在代码中**只做"存在即使用"**。具体表现为：
  1. **无哈希比对**：下载完成后直接 `ReadAsJson` / `Write` 使用，从不计算并与预期哈希比对；
  2. **无数字签名验证**：未出现任何 RSA/ECDSA 等非对称签名校验逻辑；
  3. **无证书固定（certificate pinning）**：即便启用了 TLS，也不绑定特定服务器证书，无法抵御持有合法 CA 证书的攻击者；
  4. **本地缓存同样无校验**：第 27 行读取本地缓存配置时仅 `Val(ServerConfig("Version"))`，不验证缓存是否被篡改。
  这一缺失是整个信任模型缺陷的"落地"环节：前面所有"服务器可控"的攻击面（PCL-RCE-002/003、PCL-CHAIN-001）都依赖此处的"无条件信任下载内容"才能生效。它让 MITM 或桶失陷的攻击者可以替换任意下载物。
- **可能的利用方法**：
  - 结合 MITM 或桶失陷，替换下载内容为伪造配置/公告/更新程序；
  - 客户端直接信任并使用被篡改内容。
- **可能的后果**：配置/公告被伪造；为 RCE（PCL-RCE-003）、设置篡改（PCL-RCE-002）提供数据基础。
- **严重程度**：🔴 高危

### PCL-MITM-001 传输层校验未知（自定义 HTTP 客户端可能禁用 TLS 校验）
- **类型**：中间人攻击（MITM）前置风险
- **源代码**：
  ```vb
  41   ServerContent = NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.cfg{CDN}")
  81   NetDownloadByClient("https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json{CDN}", LocalConfigPath)
  96   NoticeContent = NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.json{CDN}", RequireJson:=True)
  ```
- **说明**：所有网络请求都通过本文件**外部**的封装函数 `NetRequestByClientRetry` / `NetDownloadByClient` 发出。这些自定义 HTTP 客户端的具体行为（尤其是 TLS 证书校验策略）不在本文件可见范围内，因此无法确认。但是，在不少 Windows 桌面程序/启动器中，为了兼容自签名证书、内部 CDN 或老旧系统，开发者常会设置 `ServicePointManager.ServerCertificateValidationCallback = Function(s, cert, chain, err) True`，即**无条件接受任何证书**。一旦如此：
  1. 本文件中所有 `https://` 请求的加密保护形同虚设；
  2. PCL-DL-001（无完整性校验）与 PCL-INFO-001（标识外发）的隐患立即从"理论"变为"现实可利用"——攻击者在用户网络路径上做 ARP 欺骗、恶意热点、透明代理即可实时篡改配置/公告/更新，并截获 `Identify`；
  3. 由于没有任何证书固定，即便攻击者使用合法 CA 签发的证书也能成功伪装。
  此项需结合 `NetRequestByClientRetry`/`NetDownloadByClient` 的真实实现确认；但在"无完整性校验"的大前提下，它属于**未缓解的高危前置条件**。
- **可能的利用方法**：
  - 在用户网络路径上进行 ARP 欺骗 / 恶意热点 / 代理注入；
  - 因证书校验被禁用，伪造的 HTTPS 响应被客户端接受。
- **可能的后果**：所有下载内容（配置、公告、更新）被实时篡改，直接触发上述 RCE 与信息泄露。
- **严重程度**：🟠 中危（需结合外部实现确认，但属未缓解的高危前置条件）

### PCL-PARSE-001 不安全的响应解析（基于位置的 Split("|")）
- **类型**：输入解析脆弱 / 逻辑错误
- **源代码**：
  ```vb
  42   ServerId = Val(ServerContent.Split("|")(0))
  ...
  78   Dim ServerConfigVersion As Double = Val(ServerContent.Split("|")(4))
  ...
  43   If ServerId = 0 Then Throw New Exception("获取到的内容有误！（" & ServerContent & "）")
  ```
- **说明**：`notice.cfg` 的内容被约定为用 `|` 分隔的多段文本，代码用 `Split("|")` 按**固定位置索引**取字段：第 42 行取 `(0)`（公告编号），第 78 行取 `(4)`（配置版本号，即第 5 段）。这种"位置依赖"解析非常脆弱：
  1. **越界崩溃风险**：若服务器返回的内容字段数不足 5 段，第 78 行 `(4)` 会抛 `IndexOutOfRangeException`。虽然被第 84 行的 `Catch` 捕获（仅告警），但后果是**配置永远无法更新**，形成隐蔽的功能失效窗口，便于攻击者在此期间投毒而不被新配置覆盖。
  2. **`Val()` 边界歧义**：`Val()` 在 VB 中遇到首个非数字字符即停止并转换之前的部分。例如 `Val("0abc")` 返回 `0`，`Val("abc123")` 也返回 `0`。第 43 行用 `ServerId = 0` 来判定"内容有误"，但合法的 `ServerId` 完全可能就是 `0`，而畸形内容也可能因 `Val` 解析为 `0` 被误判——存在"有效 0 / 无效 0"的判定歧义，可被用来构造绕过校验的恶意 `notice.cfg`。
  3. **无字段数/格式校验**：解析前未验证分段数量与每段的数据类型，完全信任远端格式。
- **可能的利用方法**：
  - 下发格式异常的 `notice.cfg`，使客户端解析异常并退化为"无配置"，或错误判定版本导致永不更新（隐蔽失效）；
  - 利用 `Val` 边界歧义构造被误判为"有效"的恶意内容。
- **可能的后果**：客户端配置更新逻辑被破坏；为后续投毒创造窗口；可用性受损。
- **严重程度**：🟠 中危

### PCL-PARSE-002 反序列化类型混淆（JSON 缺 Schema 校验）
- **类型**：不安全反序列化 / 类型混淆
- **源代码**：
  ```vb
  108  For Each Notice As JObject In NoticeContent.Replace("{UNIQUE}", Identify).DeserializeJson()
  110      Dim NoticeId As Integer = Val(If(Notice("id"), 0))
  119      Dim ImportantLevel As Integer = If(Notice("importantLevel"), 2)
  124      Dim Title As String = If(Notice("title"), "公告").ToString
  ...
  161      Settings.Set(Value.Key, Value.Value.ToString)
  ```
- **说明**：对服务器下发的 JSON 公告对象，代码仅用 `Val(...)` / `If(..., 默认值)` 做**隐式强制转换**，缺少任何 Schema 或类型约束，导致多种类型混淆问题：
  1. **过滤逻辑失效**：第 110 行 `NoticeId = Val(If(Notice("id"), 0))` 与第 111 行 `If NoticeId <= LocalId Then Continue For` 共同构成公告去重/过滤。若服务器返回字符串型 `"id":"100"`，`Val` 尚可解析；但如果返回的是对象/数组型，`Val` 返回 `0`，使 `NoticeId <= LocalId` **恒成立**，导致**所有公告被跳过或误判**，用户屏蔽策略（如不过某重要级公告）可被绕过或功能被悄悄破坏。
  2. **重要级判断可被操纵**：第 119 行 `ImportantLevel` 同样依赖 `Val`/`If`，类型异常会落到默认值 `2`，可能使高重要级公告被降级显示或反之。
  3. **设置类型污染**：在 `setup`（第 161 行）中，`Value.Value.ToString` 不论原值是数字、布尔还是对象/数组，统一转字符串写入设置存储；若某值是 `JObject`/`JArray`，`.ToString` 会得到 JSON 文本，污染设置系统，引发后续逻辑异常甚至崩溃。
  4. **动作参数非预期**：`website`/`copy` 的 `Action.Value.ToString`（第 153/155 行）若值为对象，则 `OpenWebsite` 收到的将是 JSON 字符串而非 URL，行为不可预期。
  这些问题本质都是"对不可信远端输入做无约束反序列化/转换"。
- **可能的利用方法**：
  - 下发类型异常的字段，使公告过滤、重要级判断失效，绕过用户屏蔽策略；
  - 通过 `setup` 写入非标量值污染设置存储，引发后续逻辑异常。
- **可能的后果**：公告/过滤机制被绕过；设置类型污染导致不可预期行为甚至崩溃。
- **严重程度**：🟠 中危

### PCL-HARD-001 硬编码远端地址（单点信任 / 单点故障）
- **类型**：硬编码凭据 / 单点信任
- **源代码**：
  ```vb
  41   ServerContent = NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.cfg{CDN}")
  81   NetDownloadByClient("https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json{CDN}", LocalConfigPath)
  96   NoticeContent = NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.json{CDN}", RequireJson:=True)
  ```
- **说明**：远端 COS 桶地址 `pcl2-server-1253424809.file.myqcloud.com` 在代码中**硬编码了 3 处**（第 41/81/96 行），且都带 `{CDN}` 占位符由客户端运行时替换。其风险在于：
  1. **单点信任**：所有可信内容（公告、配置、更新元数据）都来自这一个桶。一旦该桶被入侵、被误删、或被云平台权限配置错误暴露，攻击面立即覆盖**全部客户端**，且无任何备用信任根或交叉验证。
  2. **单点故障 + DNS 劫持**：若该域名（或其上层 `myqcloud.com`/腾讯云账户）被劫持或 DNS 被污染，请求将被导向攻击者服务器，结合 PCL-DL-001（无校验）直接造成全量投毒。
  3. **不可轮换**：地址写死在二进制中，紧急替换信任源需要发版，响应迟缓。
  这本身不是"漏洞利用点"，但它是前述所有服务器可信类漏洞的**集中承载点**，显著放大了任一失陷事件的爆炸半径。
- **可能的利用方法**：攻破/接管该 COS 桶，或劫持 `pcl2-server-1253424809.file.myqcloud.com` 的 DNS 解析。
- **可能的后果**：全量客户端被投毒，构成大规模供应链攻击入口。
- **严重程度**：🟠 中危

### PCL-CHAIN-001 链式远程代码执行（{CDN} 替换与 setup 组合）
- **类型**：远程代码执行（攻击链）
- **源代码**：
  ```vb
  41   ServerContent = NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.cfg{CDN}")
  ...
  158  Case "setup" '仅支持 >= 388
  159      Dim Values As JObject = Action.Value
  160      For Each Value In Values
  161          Settings.Set(Value.Key, Value.Value.ToString)
  162      Next
  ```
- **说明**：`{CDN}` 是一个在请求发送前由客户端替换的占位符（替换逻辑位于 `NetRequestByClientRetry` 内部，本文件不可见）。如果 `{CDN}` 最终解析出的域名/基址由**可经 `setup` 动作改写的设置项**决定（这是需要在外部实现中确认的关键假设），则会形成一条干净的 RCE 攻击链：
  1. 攻击者通过 PCL-RCE-002 的 `setup` 改写控制 `{CDN}` 解析结果的设置（例如 CDN 域名、更新基址）；
  2. 此后所有带 `{CDN}` 的请求（第 41/81/96 行，含 `ServerConfig.json` 与最终更新）都被重定向到攻击者控制的基础设施；
  3. 攻击者在该基础设施上返回恶意 `ServerConfig.json` 或 `update.exe`，由 PCL-RCE-003 落地执行。
  这条链的可怕之处在于：即便官方修复了硬编码桶地址（PCL-HARD-001），攻击者也无需攻破腾讯云桶，只要能改写本地一处设置即可完成重定向，隐蔽性更强、持久性更好。若确认 `{CDN}` 受设置控制，本项应升为 🔴 高危。
- **可能的利用方法**：
  - 先通过 `setup` 改写 CDN/更新源相关设置；
  - 使后续请求全部指向攻击者服务器，下发恶意更新。
- **可能的后果**：稳定的 RCE 通道；即使修复单点桶地址，仍可通过设置重定向绕过。
- **严重程度**：🟠 中危（需核查 `{CDN}` 解析来源是否受设置控制；若是则升为高危）

### PCL-FILE-001 不安全临时文件写入（固定路径 + 远端内容）
- **类型**：不安全文件操作（竞态 / 符号链接）
- **源代码**：
  ```vb
  23   Dim LocalConfigPath As String = PathTemp & "Cache\ServerConfig.json"
  39   Dim NoticeFileAddress As String = PathTemp & "Cache\Notice.cfg"
  61   FileUtils.Write(NoticeFileAddress, ServerContent)
  82   ServerConfig = FileUtils.ReadAsJson(LocalConfigPath)
  97   FileUtils.Write(PathTemp & "Cache\Notice.json", NoticeContent)
  ```
- **说明**：所有缓存文件都写入**完全可预测**的固定路径 `PathTemp & "Cache\..."`，内容则来自服务器可控数据（`ServerContent`/`NoticeContent`），且写入方式（`FileUtils.Write`）大概率不是原子写（先删后写或覆盖写）。在以下场景中具有实际风险：
  1. **符号链接 / junction 预置**：在共享计算机、多用户环境或已存在低权限写入能力的场景下，攻击者可预先在 `Cache\` 目录对应位置放置指向敏感文件（如 `Hosts`、`autoexec`、计划任务目录）的符号链接或 NTFS junction；当程序执行 `FileUtils.Write` 写入该路径时，内容会被重定向写入被链接的目标文件，造成任意文件写入/覆盖。
  2. **TOCTOU 竞态**：在"先读后写"或"先删后写"之间存在时间窗，本地恶意进程可在此窗口替换文件或链接。
  3. **远端内容 + 固定路径组合**：被写入的数据本身来自不可信源，再叠加可预测的落盘位置，放大了上述攻击的可行性。
  在普通单用户桌面环境下风险较低，但在多用户/被部分攻陷的主机上不容忽视。
- **可能的利用方法**：
  - 在目标目录预置符号链接/junction 将固定路径指向敏感文件；
  - 利用竞态窗口在写入瞬间替换内容。
- **可能的后果**：任意文件写入/覆盖（取决于权限），可能被用于权限提升或持久化。
- **严重程度**：🟡 低危（普通单用户环境风险较低，但应避免远端内容 + 固定路径 + 无原子写入）

### PCL-LOG-001 日志信息泄露（含远端原始内容）
- **类型**：日志泄露
- **源代码**：
  ```vb
  45   Logger.Info($"本地公告编号：{LocalId}，服务器公告：{ServerContent}，需更新")
  ...
  180  Logger.Warn(NoticeContent)
  181  Logger.Error(ex, $"读取 PCL 服务器公告失败（{NoticeContent.Length}）", LogBehavior.Toast)
  ```
- **说明**：日志中多处写入了**远端原始响应内容**：第 45 行把完整的 `ServerContent`（即 `notice.cfg` 原文，可能含追踪参数、内部版本号、服务器结构）记录进 Info 日志；第 180–181 行在解析失败时将 `NoticeContent` 原文写入 Warn/Error 日志。其风险在于：
  1. **二次扩散**：若这些日志被自动收集、上传至开发者服务器，或用户按教程把日志文件发送给支持人员/公开到论坛，则服务器下发的内部结构、参数、甚至潜在的 `{UNIQUE}` 替换残留会被扩散出去；
  2. **泄露面有限但仍存在**：需注意第 108 行的 `{UNIQUE}` → `Identify` 替换，是作用在 `NoticeContent` 的**局部重新赋值**之后，而第 180 行的 `NoticeContent` 变量在被赋值前引用（实际使用的是循环变量 `Notice` 派生内容前的原始 `NoticeContent`），通常仍含 `{UNIQUE}` 占位符而非真实 `Identify`，因此真实设备指纹直接落日志的概率较小，但服务器结构信息仍会被记录；
  3. **Toast 提示**：第 181 行还带 `LogBehavior.Toast`，可能向用户短暂展示原文，造成界面层信息暴露。
- **可能的利用方法**：诱导或被动收集包含敏感参数的日志文件并外传。
- **可能的后果**：设备标识、内部结构、服务器下发的动作细节被二次扩散。
- **严重程度**：🟡 低危

### PCL-INFO-002 兼容性提示误导（FIPS 文案歧义）
- **类型**：信息/可用性（非直接安全）
- **源代码**：
  ```vb
  63   If TypeOf ex Is InvalidOperationException AndAlso ex.Message.Contains("FIPS") Then
  64       If MyMsgBox("由于系统未启用 FIPS 兼容算法，PCL 可能无法正常运行。" & vbCrLf &
  65                   "请按照教程启用该功能，然后重启 PCL。", "兼容性警告", "打开教程", "取消", IsWarn:=True) = 1 Then
  66           OpenWebsite("https://blog.csdn.net/qq_37608398/article/details/81209922")
  67       End If
  ```
- **说明**：代码捕获 `InvalidOperationException` 且消息含 "FIPS" 时，弹窗提示用户"由于系统未启用 FIPS 兼容算法"去开启 FIPS。但实际情况是：.NET 中 FIPS 相关异常**大多出现在系统"已启用" FIPS 模式**时（因为某些算法在该模式下被禁用而抛异常），而非"未启用"。因此文案与真实成因**相反**，容易误导用户做出错误的系统配置（如启用 FIPS 反而可能破坏更多软件的加密兼容性）。安全层面直接风险很低，但：① 它把用户引导至一个**第三方 CSDN 博客链接**（外部依赖，链接内容不受控、可能变更或失效）；② 若该 `OpenWebsite` 实现未限制协议，理论上存在被复用为 `file://` 等本地访问入口的极小风险（与 PCL-RCE-001 同源）。归类为信息级问题。
- **可能的利用方法**：若 `OpenWebsite` 可被 `file://` 等协议利用，理论上可借该提示触发本地文件/程序访问（风险极低）。
- **可能的后果**：用户被误导进行错误系统配置；轻微外部依赖风险。
- **严重程度**：⚪ 信息

### PCL-INFO-003 自复制行为（Latest.exe 固化）
- **类型**：供应链（信息）
- **源代码**：
  ```vb
  54   FileUtils.Copy(PathExe, PathTemp & "Latest.exe")
  ```
- **说明**：在版本升高且本地尚无 `Latest.exe` 时（第 50–58 行，仅 `RELEASE` 编译），程序把自身可执行文件复制为 `PathTemp & "Latest.exe"`，作为"最新正式版"缓存用于更新/回滚。该行为本身是正常的版本管理，不是漏洞；但需指出其供应链含义：`Latest.exe` 的来源就是**当前正在运行的进程自身**。因此，一旦当前 `exe` 已经被供应链攻击污染（例如通过 PCL-RCE-003 安装的恶意更新），这一复制会把污染版本"固化"为"官方最新版"缓存，使得普通的重新更新/回滚操作无法清除污染，反而持续保留恶意版本。这属于在**前置供应链失陷**条件下的风险放大器，归为信息级。
- **可能的利用方法**：在供应链已污染的前提下，使其"最新正式版"缓存持续为恶意版本。
- **可能的后果**：污染版本被固化，难以通过普通更新回滚清除。
- **严重程度**：⚪ 信息

---

## 三-B、Backdoor（后门）的猜测

火绒论坛上有用户将本模块判为 Backdoor 风险，依据的是其**静态启发式**对"远程命令与控制（C2）+ 静默自更新 + 自复制 + 设备回传"行为模式的识别。本代码虽为 PCL2 启动器的合法设计，但下列结构在技术上完全符合"后门 / 远程控制程序"的定义：

1. **远程命令执行分发器（核心证据）** — 第 41/96/108 行从服务器拉取 `notice.json` 并 `DeserializeJson()`，第 149–177 行遍历其中的 `actions` 并按 `Action.Name` 动态分发执行。即"程序接收远端下发的指令并直接执行"，是后门最典型的"接收命令→执行"特征。
2. **静默（无界面）执行通道** — 第 145–147 行：当公告无 `buttons` 时直接 `Actions = If(Notice("actions"), {})` 并自动执行，无需任何用户交互 / 确认。
3. **静默下载并执行更新（落地 RCE）** — 第 14–15 行启动时删除 `PCL\update.exe`，第 163–170 行由服务器 `update`/`slientupdate` 动作触发 `UpdateStart(Silent)`，结合第 81 行下载的无签名 `ServerConfig.json`（更新源由服务器决定），构成"远程投送并运行任意可执行文件"的经典后门持久化 / 更新机制。
4. **自复制** — 第 54 行 `FileUtils.Copy(PathExe, PathTemp & "Latest.exe")`：将自身复制为 `Latest.exe`，触发 AV 启发式中的"自我复制"后门 / 病毒行为特征。
5. **设备指纹回传（隐蔽追踪）** — 第 108 行 `Replace("{UNIQUE}", Identify)` 将持久设备标识嵌入公告内容，配合每次 HTTPS 请求的 `?id=Identify` 回传服务器，实现跨会话追踪。

**结论**：代码本身未见"隐藏的硬编码 C2 或密文指令"等蓄意植入痕迹（属 PCL2 官方架构），但其**服务器可信的远程动作框架 + 自更新 + 自复制**在行为层面与后门 / RAT 等价，这正是火绒给出 Backdoor 判定的原因。此结论与前述"无蓄意后门、但风险不亚于后门"的总体判断一致。

---

## 四、漏洞汇总表

| 编号 | 名称（类型） | 类型 | 严重程度 |
|---|---|---|---|
| PCL-RCE-001 | 远程代码执行（无约束动作通道） | 远程代码执行 | 🔴 高危 |
| PCL-RCE-002 | 权限提升/任意设置篡改（setup） | 权限提升 | 🔴 高危 |
| PCL-RCE-003 | 不安全更新机制（update/slientupdate） | 远程代码执行 | 🔴 高危 |
| PCL-SILENT-001 | 静默执行危险动作（无 buttons） | 远程控制 | 🔴 高危 |
| PCL-DL-001 | 下载内容无完整性校验 | 缺少校验 | 🔴 高危 |
| PCL-DOS-001 | 远程拒绝服务（stop） | 拒绝服务 | 🟠 中危 |
| PCL-INFO-001 | 信息泄露（设备指纹外发） | 信息泄露 | 🟠 中危 |
| PCL-MITM-001 | 传输层校验未知（TLS 可能禁用） | 中间人 | 🟠 中危 |
| PCL-PARSE-001 | 不安全响应解析（Split） | 解析脆弱 | 🟠 中危 |
| PCL-PARSE-002 | 反序列化类型混淆（JSON） | 类型混淆 | 🟠 中危 |
| PCL-HARD-001 | 硬编码远端地址（单点信任） | 单点信任 | 🟠 中危 |
| PCL-CHAIN-001 | 链式 RCE（{CDN}+setup） | 远程代码执行 | 🟠 中危* |
| PCL-FILE-001 | 不安全临时文件写入 | 文件竞态 | 🟡 低危 |
| PCL-LOG-001 | 日志信息泄露 | 日志泄露 | 🟡 低危 |
| PCL-INFO-002 | 兼容性提示误导（FIPS） | 信息 | ⚪ 信息 |
| PCL-INFO-003 | 自复制行为（Latest.exe） | 供应链 | ⚪ 信息 |

\* PCL-CHAIN-001 若确认 `{CDN}` 受 `setup` 可写设置控制，应升为 🔴 高危。

---

## 五、加固建议

1. **更新/配置强校验（最关键）**
   - 对 `ServerConfig.json`、`notice.json`、`notice.cfg` 及 `update.exe` 引入非对称签名校验（内置公钥验证 RSA/ECDSA）与哈希比对；对 `update.exe` 增加 Authenticode/发布者校验，必要时证书固定。
   - 更新源地址改为**编译期固化**的可信域名/路径，禁止由服务器下发的 `ServerConfig` 任意指定可执行下载地址。
2. **收紧动作框架（最小权限 + 显式同意）**
   - `setup` 增加键名白名单（仅允许非安全敏感设置）并对值做类型/范围校验；禁止修改更新源、`{CDN}`、代理、版本阈值等。
   - 无 `buttons` 公告的顶层 `actions` 默认不自动执行或要求用户确认；`website`/`copy`/`stop`/`setup` 执行前弹出明确告知。
   - `website` 仅允许 `http(s)`，禁止 `file://`、`javascript:`、`UNC`。
3. **传输安全**：确认底层 HTTP 客户端未禁用 TLS 证书校验；如需兼容改为显式固定证书。对 `Identify` 做随机化/加盐降低追踪。
4. **健壮性/解析安全**：用结构化解析替代 `Split("|")` 位置索引；所有远端 JSON 字段做显式类型与 Schema 校验；`Action.Value` 按动作类型分别校验。
5. **基础设施与部署**：提取硬编码桶地址为多备用信任源 + 熔断；临时文件改为随机名 + 原子写并收紧目录权限。复核 `{CDN}` 替换来源是否受 `setup` 可写设置影响。
6. **可观测与响应**：记录服务器动作审计日志（动作名/来源/时间）；异常批量/高频动作时告警；发布流程对"高权限远程交互"模块加安全评审门禁。

---

## 六、说明与局限

- 本报告对 `OpenWebsite`、`UpdateStart`、`NetDownloadByClient`、`NetRequestByClientRetry`、`ClipboardSet`、`Identify`、`HasUpdatePermission`、`ServerRequirement` 等**外部符号**的行为基于调用约定与安全推理给出。
- 以下结论需在审阅其实现后最终确认：**TLS 校验是否禁用**（PCL-MITM-001）、**`{CDN}` 是否受设置控制**（PCL-CHAIN-001）、**`update.exe` 是否被执行**（PCL-RCE-003）。
- 即便上述外部函数均按最佳实践实现，本文件**缺失的服务器内容鉴权/完整性校验**与**无约束的 `setup`/动作框架**已足以构成高危风险，应优先处置。
- 原始代码未做任何修改，仅做静态分析。
