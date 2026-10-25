# ModSecret.txt 漏洞原理教程：来龙去脉与攻击链路

> 配套文档：`安全评估报告_ModSecret.md`
> 目标读者：想搞清楚"这些漏洞到底是怎么来的、怎么被利用的"的开发者 / 安全爱好者
> 代码对象：`ModSecret.txt`（PCL2 启动器联网配置/公告/更新模块，VB.NET）
>
> 备注：本教程基于PCL2.0公开的186行代码，以其为基础知识进行的合理推断。该教程内所有的漏洞是否真的存在，取决于外部函数的实现。PCL2.0作为一个很可能有着几十万行代码的庞大资产库，目前掌握的代码行数仅为其核心逻辑中的一部分。

---

## 0. 先建立一张"全局地图"

要理解下面每一条漏洞，必须先理解这个模块的**设计初衷**和它**埋下的根因**。

### 0.1 这个模块本来要干什么？

PCL2 是一个 Minecraft 启动器。它需要在不发布新版本的情况下，做几件事：

- 给玩家弹**公告**（维护通知、活动、更新提示）；
- 从服务器拉取**最新配置**（`ServerConfig.json`，控制各种行为开关）；
- 必要时**静默/显式地更新自己**。

于是开发者设计了一个后台任务 `ServerSub`，周期性地：

1. 清理旧的 `update.exe`（第 14–15 行）；
2. 读本地缓存配置与公告；
3. 向腾讯云 COS 桶 `pcl2-server-1253424809.file.myqcloud.com` 拉取 `notice.cfg`、`ServerConfig.json`、`notice.json`；
4. 解析服务器下发的"公告 JSON"，并执行其中声明的**动作（actions）**。

### 0.2 根因：一个"完全信任服务器"的信任模型

整个模块的隐含假设是：**"服务器是我自己控制的，它下发的任何东西都是可信的。"**

于是代码里出现了这样一条逻辑链：

```
服务器下发配置/公告 → 客户端直接信任 → 解析成动作 → 立刻执行
```

这条链上**没有任何一道"验明正身"的关卡**：

- 不验证内容是否由真正的 PCL 服务器签名；
- 不校验下载文件的哈希；
- 不校验 HTTPS 证书是否真的属于该服务器（取决于底层 HTTP 客户端实现）；
- 不限制"服务器能命令客户端做什么"。

**所有后续的漏洞，都是这个根因在不同位置的开花结果。** 记住这一点，下面每一条都能顺着这根藤摸到瓜。

---

## 1. 远程代码执行（RCE）类

> 这一类是整套代码里最危险的部分，本质上是一个"服务器可远程命令客户端"的框架。

### 1.1 PCL-RCE-001：无约束的服务器动作执行通道

**来龙去脉**：开发者想让服务器能"远程指挥客户端做点事"（比如引导用户打开某个页面、弹个提示）。为此他做了一个 `Select Case Action.Name` 的分发器——服务器在公告 JSON 里写 `"actions": [{"name":"website","value":"..."}]`，客户端就执行对应分支。设计意图是"方便运营"，但**没有给这个能力套上任何笼子**。

**原理**（关键代码）：

```vb
149  For Each Action As JProperty In Actions
151      Select Case Action.Name
152          Case "copy"       : ClipboardSet(Action.Value.ToString)
154          Case "website"    : OpenWebsite(Action.Value.ToString)
156          Case "stop"       : FrmMain.EndProgram(False)
158          Case "setup"      : ' 写任意本地设置
163          Case "update", "slientupdate" : UpdateStart(Silent)
```

客户端把 `Action.Name` 当指令、`Action.Value` 当参数，**原样执行**。问题在于：
- 指令集是**开放**的（`Case Else` 只是抛个异常然后被吞掉，见第 171–176 行），服务器随时能加新动作；
- 参数**完全由服务器决定**，客户端不筛选、不白名单。

**攻击链路**：攻击者控制 COS 桶（或 MITM 响应）→ 下发含 `update`/`setup` 的公告 → 客户端照单执行 → 远程控制成立。

**危害**：等价于一个无鉴权的远程命令解释器。一旦"服务器/传输"任一环节失守，全量客户端可被遥控。

---

### 1.2 PCL-RCE-002：setup 动作无白名单，可改写任意本地设置

**来龙去脉**：运营时偶尔需要"远程改一下客户端某个设置"（比如临时关掉某项功能）。于是有了 `setup` 动作。

**原理**：

```vb
158  Case "setup" '仅支持 >= 388
159      Dim Values As JObject = Action.Value
160      For Each Value In Values
161          Settings.Set(Value.Key, Value.Value.ToString)
162      Next
```

它把服务器下发的 JSON 对象**逐字段**写入本地设置存储，**没有任何键名白名单、类型校验、安全键拦截**。注意：注释"仅支持 >= 388"只是客户端**版本门槛**，不是安全控制——服务器知道你的版本，专挑兼容的客户端下发即可。

**为什么危险**：如果设置系统里存在"更新源""CDN 域名""代理""公告过滤阈值"这类键，攻击者就能通过 `setup` 偷偷改掉它们，为后续 RCE 铺路（见 1.5）。

**攻击链路**：`setup` 改写 CDN/更新源设置 → 后续下载全被重定向到攻击者服务器 → 投毒。

**危害**：持久化篡改客户端行为，绕过用户屏蔽策略，是 RCE 链条上的"扳机"。

---

### 1.3 PCL-RCE-003：不安全的更新机制（update/slientupdate 触发下载执行）

**来龙去脉**：启动器需要自我更新。早期版本可能用公告里的 URL 直接更新，后来改成"从 `ServerConfig.json` 读更新信息"（第 163 行注释明示）。

**原理**：

```vb
14   If FileUtils.Exists(Paths.Base & "PCL\update.exe") Then
15       FileUtils.Delete(Paths.Base & "PCL\update.exe")   ' 清理旧更新包
...
81   NetDownloadByClient("...ServerConfig.json{CDN}", LocalConfigPath)  ' 下载配置(无校验)
...
163  Case "update", "slientupdate"   ' 更新源改从 ServerConfig.json 读取
170      UpdateStart(Silent)
```

关键事实链：
1. 启动时删 `PCL\update.exe`（第 14–15 行）→ 说明该路径是**更新器预期的执行入口**；
2. 更新信息来自 `ServerConfig.json`，而该 JSON 是**服务器下发且无签名校验**的（见 2.1）；
3. 公告里的 `update`/`slientupdate` 动作触发 `UpdateStart` → 下载并运行更新程序。

**攻击链路**：篡改 `ServerConfig.json` 的更新源 → 触发 `update` 动作 → 下载攻击者控制的 `update.exe` → 以启动器同等权限执行 → **RCE**。

**危害**：直接拿到代码执行权限。这是整条链最"落地"的一环。

---

### 1.4 PCL-SILENT-001：无 buttons 公告 → 静默执行危险动作

**来龙去脉**：正常公告有按钮，用户点哪个按钮、执行哪组动作，至少有"一次点击"。但代码为"无按钮公告"留了另一条路。

**原理**：

```vb
129  If ButtonCount > 0 Then
144      Actions = If(Buttons(MsgBoxResult - 1)("actions"), {})  ' 用户点过按钮
145  Else
146      Actions = If(Notice("actions"), {})                     ' 直接用顶层 actions
147  End If
149  For Each Action As JProperty In Actions
```

当公告**没有 `buttons`** 时，走入 `Else`，直接用公告顶层的 `actions`，并在**无任何弹窗、无用户点击**的情况下自动执行。

**为什么危险**：服务器只要不下发按钮，就能让客户端"悄无声息"地打开网页、改剪贴板、强制退出、改设置。

**攻击链路**：下发无按钮公告 → 客户端静默执行 `website`/`copy`/`setup`/`stop` → 用户无感知。

**危害**：把 1.1 的风险放大成"零交互、不可见"版本，是社工与隐蔽攻击的温床。

---

### 1.5 PCL-CHAIN-001：{CDN} + setup 链式 RCE

**来龙去脉**：请求 URL 里有个 `{CDN}` 占位符，发出前由客户端替换成真实域名（替换逻辑在外部函数里）。

**原理假设**：如果 `{CDN}` 最终解析出的域名，是由**可经 `setup` 改写的设置**决定的，那就形成一条干净利落的攻击链：

```
setup 改写 CDN 设置
   → 后续所有带 {CDN} 的请求(含 ServerConfig.json / update.exe) 被重定向到攻击者服务器
   → 攻击者返回恶意更新 → PCL-RCE-003 落地
```

**为什么这条链尤其阴险**：即便官方把硬编码的 COS 桶地址修掉（见 2.3），攻击者也无需攻破腾讯云——只要能改本地一处设置即可完成重定向，隐蔽、持久。

**攻击链路**：见上。需确认 `{CDN}` 来源是否受设置控制（外部实现未审阅，待定）。

**危害**：稳定的 RCE 通道。若确认，本项应升为高危。

---

## 2. 下载 / 传输 / 信任根类

### 2.1 PCL-DL-001：下载内容无完整性校验

**来龙去脉**：为了"简单"，下载完配置/公告/更新就直接用，没做校验。

**原理**：

```vb
27   LocalConfigVersion = Val(ServerConfig("Version"))   ' 读本地缓存也不校验
81   NetDownloadByClient("...ServerConfig.json{CDN}", LocalConfigPath)
82   ServerConfig = FileUtils.ReadAsJson(LocalConfigPath)  ' 下载完直接反序列化使用
96   NoticeContent = NetRequestByClientRetry("...notice.json{CDN}", RequireJson:=True)
```

代码里**没有**哈希比对、没有数字签名验证、没有证书固定。下载到什么就用什么。

**为什么危险**：这是"服务器可信"假设在落地的最后一环的崩塌——前面所有"服务器可控"的攻击面，都靠"下载内容无条件被信任"才能生效。

**攻击链路**：MITM 或桶失陷 → 替换下载内容 → 客户端照用 → 配置/公告/更新全被伪造。

**危害**：为 RCE、设置篡改提供数据基础。

---

### 2.2 PCL-MITM-001：传输层校验未知（TLS 可能被动过手脚）

**来龙去脉**：所有请求走自定义 HTTP 客户端封装 `NetRequestByClientRetry`/`NetDownloadByClient`。这些函数的 TLS 行为不在本文件可见范围。

**原理与隐患**：很多 Windows 桌面程序为了兼容自签名证书 / 老旧系统，会写：

```vb
ServicePointManager.ServerCertificateValidationCallback = Function(...) True  ' 接受任何证书
```

一旦如此，所有 `https://` 的加密保护**形同虚设**。

**攻击链路**：用户在恶意热点/被 ARP 欺骗的网络下 → 攻击者伪造 HTTPS 证书 → 因校验被禁用，伪造响应被接受 → 实时篡改配置/公告/更新，并截获设备标识。

**危害**：把 2.1、2.3、信息泄露全部从"理论"变成"现实可利用"。属高危前置条件。

---

### 2.3 PCL-HARD-001：硬编码远端地址（单点信任 / 单点故障）

**来龙去脉**：COS 桶地址直接写死在三处请求里，图省事。

**原理**：

```vb
41   NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.cfg{CDN}")
81   NetDownloadByClient("https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json{CDN}", ...)
96   NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.json{CDN}", ...)
```

**为什么危险**：所有可信内容来自**同一个桶**。它一旦被入侵 / DNS 被劫持 / 权限配错，**全部客户端**立刻暴露，且**没有备用信任根**可切换。

**攻击链路**：攻破或劫持该桶 → 全量客户端被投毒。

**危害**：供应链攻击的集中承载点，爆炸半径极大。

---

## 3. 信息泄露类

### 3.1 PCL-INFO-001：设备指纹外发

**来龙去脉**：为了做"每设备"的统计/追踪，客户端持有稳定标识 `Identify`（安装 ID 或硬件指纹）。

**原理**：

```vb
108  For Each Notice As JObject In NoticeContent.Replace("{UNIQUE}", Identify).DeserializeJson()
```

客户端把公告里的 `{UNIQUE}` 占位符替换成真实 `Identify`；结合 PCL2 既有请求约定（URL 通常追加 `?v=版本&id=Identify`），`Identify` 与版本号**极可能随每次 HTTPS 请求明文发往服务器**。

**攻击链路**：服务器收集 `Identify` → 跨会话追踪、画像、定位用户；若 TLS 被弱化（2.2），传输中被中间人截获。

**危害**：长期隐私泄露。HTTPS 下主要表现为"服务器端可追踪性"，MITM 下升级为实时泄露。

---

### 3.2 PCL-LOG-001：日志含远端原始内容

**来龙去脉**：调试方便，把服务器返回的原始内容写进日志。

**原理**：

```vb
45   Logger.Info($"本地公告编号：{LocalId}，服务器公告：{ServerContent}，需更新")
180  Logger.Warn(NoticeContent)
```

**为什么危险**：日志若被用户发给客服、或上传、或公开到论坛，服务器下发的内部结构、参数就被扩散出去。注：`{UNIQUE}` 替换发生在 `NoticeContent` 重新赋值之前，第 180 行通常仍含占位符而非真实 `Identify`，泄露面有限但仍存在。

**攻击链路（反向）**：攻击者诱导用户发送含敏感参数的日志 → 获取服务器结构/用户环境信息。

**危害**：信息二次扩散。

> **延伸阅读**：PCL 历史上**真实出过**同类问题——CVE-2025-54120（社区版把第三方登录凭据写入日志，CVSS 9.3 严重）、GHSA-22mj-jjhv-rxm4（日志含 Minecraft AccessToken）。说明"日志乱写敏感数据"是 PCL 的**系统性短板**，不是孤例。

---

### 3.3 PCL-INFO-002：FIPS 兼容性提示文案误导

**来龙去脉**：为兼容特定系统加密配置，捕获 FIPS 异常并弹窗引导用户开 FIPS。

**原理**：

```vb
63   If TypeOf ex Is InvalidOperationException AndAlso ex.Message.Contains("FIPS") Then
65       OpenWebsite("https://blog.csdn.net/qq_37608398/article/details/81209922")
```

**问题**：.NET 中 FIPS 异常**多在"已启用 FIPS"时**因算法被禁用而抛，文案却写"未启用 FIPS"，因果相反，易误导用户做错误系统配置；且引导至第三方博客（外部依赖）。

**危害**：可用性 / 轻微外部依赖风险，非直接安全漏洞（信息级）。

---

### 3.4 PCL-INFO-003：自复制 Latest.exe 固化

**来龙去脉**：版本升高时把自身复制为 `Latest.exe` 作"最新正式版"缓存，用于回滚。

**原理**：

```vb
54   FileUtils.Copy(PathExe, PathTemp & "Latest.exe")
```

**为什么值得记一笔**：`Latest.exe` 来源就是当前运行的进程。**若当前 exe 已被供应链污染**，这一复制会把污染版本"固化"为官方缓存，普通更新/回滚难以清除。

**危害**：前置供应链失陷时的风险放大器（信息级）。

---

## 4. 解析与健壮性类

### 4.1 PCL-PARSE-001：基于位置的 Split("|") 脆弱解析

**来龙去脉**：`notice.cfg` 被约定为 `|` 分隔的多段文本，代码按固定下标取字段。

**原理**：

```vb
42   ServerId = Val(ServerContent.Split("|")(0))          ' 取第 1 段
78   Dim ServerConfigVersion As Double = Val(ServerContent.Split("|")(4))  ' 取第 5 段
43   If ServerId = 0 Then Throw New Exception("获取到的内容有误！")
```

**两处隐患**：
1. **越界**：字段不足 5 段时，第 78 行 `(4)` 抛 `IndexOutOfRangeException`；虽被捕获，但后果是"配置永远不更新"，形成投毒窗口。
2. **`Val` 歧义**：`Val("abc123")` 返回 `0`，而第 43 行用 `ServerId = 0` 判"内容有误"——合法 ID 也可能是 0，畸形内容也可能被 `Val` 解析成 0，**"有效 0 / 无效 0"** 判定被混淆，可被用来构造绕过校验的恶意 `notice.cfg`。

**危害**：配置更新逻辑被破坏，为后续投毒创造窗口。

---

### 4.2 PCL-PARSE-002：JSON 反序列化类型混淆

**来龙去脉**：服务器下发的公告 JSON 字段，代码只用 `Val(...)` / `If(..., 默认值)` 隐式强转，没有 Schema 约束。

**原理**：

```vb
110  Dim NoticeId As Integer = Val(If(Notice("id"), 0))
119  Dim ImportantLevel As Integer = If(Notice("importantLevel"), 2)
161  Settings.Set(Value.Key, Value.Value.ToString)   ' setup 里
```

**多种类型混淆**：
- 若 `id` 是对象/数组，`Val` 返回 `0`，使 `NoticeId <= LocalId` 恒成立 → **所有公告被跳过或误判**，过滤/屏蔽策略失效；
- `ImportantLevel` 异常时落到默认 `2`，重要级判断可被操纵；
- `setup` 中 `Value.Value.ToString` 遇对象/数组会得到 JSON 文本写入设置 → **设置类型污染**；
- `website`/`copy` 的 `Action.Value.ToString` 遇对象会得到非 URL 输入，`OpenWebsite` 行为不可预期。

**危害**：公告/过滤机制被绕过，设置污染导致不可预期行为甚至崩溃。

---

## 5. 其他

### 5.1 PCL-DOS-001：stop 动作远程拒绝服务

**原理**：

```vb
156  Case "stop"
157      FrmMain.EndProgram(False)
```

服务器可随时、零确认地强制退出启动器。

**攻击链路**：在公告中混入 `stop`（尤其配合 1.4 无按钮静默执行）→ 客户端被随时关闭。

**危害**：可用性受损；可配合其他攻击做干扰。

---

### 5.2 PCL-FILE-001：不安全临时文件写入（固定路径 + 远端内容）

**原理**：

```vb
23   Dim LocalConfigPath As String = PathTemp & "Cache\ServerConfig.json"
39   Dim NoticeFileAddress As String = PathTemp & "Cache\Notice.cfg"
61   FileUtils.Write(NoticeFileAddress, ServerContent)   ' 写入服务器可控内容
```

路径**完全可预测**，内容来自服务器，且大概率非原子写。

**为什么危险**（多用户/被部分攻陷场景）：
- 预先在 `Cache\` 放符号链接 / NTFS junction 指向敏感文件 → `Write` 把内容重定向写入目标；
- TOCTOU 竞态：先删后写之间存在窗口，可被替换。

**危害**：任意文件写入/覆盖（取决于权限），可能用于提权或持久化。普通单用户环境风险较低。

---

## 6. 一张"攻击链总图"

把上面所有高危项串起来，一次典型的**全链路 RCE** 是这样的：

```
[前提] 攻击者攻破 COS 桶 / 劫持 DNS / MITM（若 TLS 校验被关）
   │
   ├─(2.3/2.2)─ 篡改 notice.cfg / ServerConfig.json / notice.json
   │
   ├─(1.4)──── 下发【无按钮公告】→ 客户端静默执行
   │
   ├─(1.2)──── setup 改写 CDN/更新源/过滤阈值等设置
   │            （或 1.5：{CDN} 重定向后续所有下载）
   │
   ├─(2.1)──── 下载内容无校验 → 全盘接受伪造配置
   │
   ├─(1.3)──── update/slientupdate 触发 UpdateStart
   │            → 下载并执行攻击者控制的 update.exe
   │
   └─(RCE)──── 以启动器权限运行任意代码
                （3.1 同时把设备指纹回传；3.2 把服务器结构写进日志）
```

而**正常运营**下，这条链因为"开发者可信"而安静地蛰伏——这正是"无蓄意后门、但风险不亚于后门"的含义。

---

## 7. 小结：这些漏洞"怎么来的"

| 根因 | 催生的漏洞 |
|---|---|
| 完全信任服务器（无签名/哈希/证书固定） | RCE-001、RCE-002、RCE-003、DL-001、MITM-001、CHAIN-001 |
| 动作框架无白名单、无用户确认 | RCE-001、SILENT-001、DOS-001 |
| 更新源由服务器内容决定 | RCE-003、CHAIN-001 |
| 单点硬编码信任 | HARD-001 |
| 设备标识默认外发 | INFO-001 |
| 日志写入敏感/远端内容 | LOG-001（且是 PCL 历史真实短板） |
| 位置式/无 Schema 解析 | PARSE-001、PARSE-002 |
| 固定可预测路径 + 远端内容 | FILE-001 |

**一句话收尾**：这些漏洞不是某人"故意埋雷"，而是"**为了方便运营而把过多信任交给了服务器**"这一善意设计，在攻击者掌控服务器/传输的假设下，自然推导出的必然结果。理解这一点，才能正确地去加固它——不是删功能，而是**给信任加上验身、加上边界、加上用户确认**。
