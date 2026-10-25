# TLS 回调实测工具

用于验证 `PCL.ModSecret` 中 `ServicePointManager.ServerCertificateValidationCallback`
在 `ToolDownloadCert` 开关下的实际行为（见主报告 6.5 节 / PCL2-2026-07）。

| 文件 | 作用 |
|---|---|
| `server.py` | 本地 HTTPS 服务（自签证书），对任意路径返回 200 |
| `probe.cs` | .NET Framework 4.8 复刻：把 URI 主机改写为 IP 直连，观察回调拿到的 `Address.Host` |

## 复现步骤

```bash
# 1) 生成一次性自签证书（仓库不存放私钥，key.pem 需本地自行生成）
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 \
        -subj "/CN=localhost"

# 2) 启动本地 HTTPS 服务（监听 127.0.0.1:8443）
python server.py

# 3) 编译并运行探针（用 .NET Framework 4.8 自带的编译器）
```

`probe.cs` 顶部注释里写了编译命令。

## 关键观察

请求 `https://127.0.0.1:8443/` 并携带 `Host: api.minecraftservices.com` 时，
回调内的 `req.Address.Host` 为 `127.0.0.1`，因此
`Address.Contains("minecraftservices")` 为 `False`——"放宽 TLS 校验"的分支不会命中。

这决定了 PCL2-2026-07 的实际影响范围只有 `minecraftservices` 这一个域，
而不是原推断的"两个域"。
