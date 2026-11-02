# PolarisSentinel

PolarisSentinel is a network intrusion detection and response prototype for Windows. It captures
inbound traffic with Npcap, extracts 20 features per flow, classifies the flow with a Random Forest
and an Isolation Forest exported to ONNX, passes the result to a policy decision engine, and blocks
the source address or port through Windows Firewall. A web dashboard shows live traffic, alerts,
policies, rules and the offline evaluation of the models.

PolarisSentinel 是一个面向 Windows 的网络入侵检测与响应原型系统。它通过 Npcap 捕获入站流量，
为每条流提取 20 个特征，使用导出为 ONNX 的随机森林和孤立森林模型进行分类，将结果交给策略
决策引擎，并通过 Windows 防火墙封锁来源地址或端口。Web 仪表盘展示实时流量、告警、策略、
规则以及模型的离线评估结果。

The scope is deliberately narrow: inbound traffic only, on one Windows host, with DoS, port scanning
and brute-force login attempts as the target attack types.

项目范围限定为单台 Windows 主机上的入站流量，目标攻击类型包括拒绝服务攻击（DoS）、端口扫描
和暴力登录尝试。

## Requirements / 环境要求

- Windows 10 1607 or later (x64), administrator rights

  Windows 10 1607 或更高版本（x64），需要管理员权限。

- .NET 10 SDK to build, or the .NET 10 runtime to run a published folder

  构建需要 .NET 10 SDK；运行已发布的程序目录需要 .NET 10 运行时。

- Npcap driver, for packet capture

  Npcap 驱动，用于捕获网络数据包。

- SQL Server LocalDB or SQL Server

  SQL Server LocalDB 或 SQL Server。
