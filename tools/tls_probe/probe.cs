// 用途：复刻 PCL2 的 ServerCertificateValidationCallback，观察 IP 直连时回调拿到的 Address.Host
// 编译：使用 .NET Framework 4.8 自带的 C# 编译器（csc.exe，位于 %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\）
//   csc /nologo probe.cs
// 运行：probe.exe          只发起请求，走默认证书校验
//       probe.exe cb       先安装回调再请求，打印 Address / Address.Host / PolicyErrors
using System;
using System.Net;
using System.Net.Http;

class Probe
{
    static void Main(string[] args)
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        bool install = args.Length > 0 && args[0] == "cb";

        if (install)
        {
            ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, err) =>
            {
                Console.WriteLine("[CB] SenderType = " + (s == null ? "null" : s.GetType().FullName));
                Console.WriteLine("[CB] PolicyErrors = " + err);
                HttpWebRequest req = s as HttpWebRequest;
                Console.WriteLine("[CB] Address = " + (req == null ? "<null>" : req.Address.ToString()));
                Console.WriteLine("[CB] Address.Host = " + (req == null ? "<null>" : req.Address.Host));
                string host = req == null ? "" : req.Address.Host;
                bool hit = host.Contains("minecraftservices");
                Console.WriteLine("[CB] Contains(minecraftservices) = " + hit);
                if (err == System.Net.Security.SslPolicyErrors.None) return true;
                // 复刻 PCL：Enabled=false 时 (xboxlive||minecraftservices) && !Enabled
                return hit;
            };
        }

        try
        {
            using (HttpClient c = new HttpClient(new HttpClientHandler()))
            {
                HttpRequestMessage rq = new HttpRequestMessage(HttpMethod.Get, "https://127.0.0.1:8443/");
                rq.Headers.Host = "api.minecraftservices.com";
                HttpResponseMessage r = c.SendAsync(rq).Result;
                Console.WriteLine("RESULT = OK " + (int)r.StatusCode);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("RESULT = FAIL " + ex.GetBaseException().GetType().Name + " :: " + ex.GetBaseException().Message);
        }
    }
}
