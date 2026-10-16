# PolarisSentinel

PolarisSentinel is a network intrusion detection and response prototype for Windows. It captures
inbound traffic with Npcap, extracts 20 features per flow, classifies the flow with a Random Forest
and an Isolation Forest exported to ONNX, passes the result to a policy decision engine, and blocks
the source address or port through Windows Firewall. A web dashboard shows live traffic, alerts,
policies, rules and the offline evaluation of the models.

The scope is deliberately narrow: inbound traffic only, on one Windows host, with DoS, port scanning
and brute-force login attempts as the target attack types.

## Requirements

- Windows 10 1607 or later (x64), administrator rights
- .NET 10 SDK to build, or the .NET 10 runtime to run a published folder
- Npcap driver, for packet capture
- SQL Server LocalDB or SQL Server

